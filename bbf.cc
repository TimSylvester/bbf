#include <secp256k1.h>
#include <bitcoin/bitcoin.hpp>
#include <bitcoin/bitcoin/math/external/ripemd160.h>
#include <bitcoin/bitcoin/math/external/sha256.h>
#include <bloom_filter.hpp>
#include <boost/filesystem.hpp>
#include <boost/regex.hpp>
#include <chrono>
#include <functional>
#include <set>
#include <string>

namespace bfs = boost::filesystem;

typedef std::set<bc::data_chunk> chunk_set;

static const boost::regex CommentPattern("^\\s*|\\s*$");

class SecretGenerator
{
public:
	virtual bc::ec_secret const& Next() = 0;
	virtual bool Done() = 0;
};

static const bc::ec_secret KeyZero = {{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

class SerialSecretGenerator : public SecretGenerator
{
private:
	bc::ec_secret	_key;

public:
	SerialSecretGenerator() : _key(KeyZero) {}
	SerialSecretGenerator(bc::ec_secret const& key) : _key(key) {}

	virtual bc::ec_secret const& Next() override
	{
		auto p0 = (uint8_t*)_key.data();
		for (int i = _key.size()/sizeof(*p0) - 1; i >= 0; --i)
		{
			auto p = p0 + i;
			if (++*p)
			{
				break;
			}
		}
		return _key;
	}
	virtual bool Done() override
	{
		return false;
	}
};

class RandSecretGenerator : public SecretGenerator
{
private:
	bc::ec_secret   _key;
	uint32_t        _seed;
	uint32_t        _maxSeed;
	int             _offset;
	int             _curOffset;
	int             _maxOffset;
	bool _word;
	bool _rev;

public:
	RandSecretGenerator(
			uint32_t seed = 0, uint32_t maxSeed = 0,
			int offset = 0, int maxOffset = 0)
		: _seed(seed)
		, _offset(offset)
		, _curOffset(offset)
		, _word(false)
		, _rev(false)
	{
		_maxSeed = (seed < maxSeed) ? maxSeed : std::numeric_limits<uint32_t>::max();
		_maxOffset = std::max(offset, maxOffset);
	}

	virtual void RandFill()
	{
		//std::cout << _rev << "/" << _word << "/" << _curOffset << "/" << _seed << std::endl;
		if (_word)
		{
			int const chunkCount = _key.size()/sizeof(uint32_t);
			if (_rev)
			{
				auto p = ((uint32_t*)_key.data()) + chunkCount - 1;
				for (int i = 0; i < chunkCount; ++i)
				{
					*p-- = rand();
				}
			}
			else
			{
				auto p = (uint32_t*)_key.data();
				for (int i = 0; i < chunkCount; ++i)
				{
					*p++ = rand();
				}
			}
		}
		else
		{
			int const chunkCount = _key.size()/sizeof(uint8_t);
			if (_rev)
			{
				auto p = ((uint8_t*)_key.data()) + chunkCount - 1;
				for (int i = 0; i < chunkCount; ++i)
				{
					*p-- = (uint8_t)rand();
				}
			}
			else
			{
				auto p = (uint8_t*)_key.data();
				for (int i = 0; i < chunkCount; ++i)
				{
					*p++ = (uint8_t)rand();
				}
			}
		}
	}

	virtual bc::ec_secret const& Next() override
	{
		std::srand(_seed);

		for (int i = 0; i < _curOffset; ++i)
		{
			rand();
		}

		RandFill();

		if (!_rev)
		{
			_rev = true;
		}
		else if (!_word)
		{
			_rev = false;
			_word = true;
		}
		else if (_offset < _maxOffset && _curOffset <= _maxOffset)
		{
			_rev = false;
			_word = false;
			++_curOffset;
		}
		else
		{
			_rev = false;
			_word = false;
			_curOffset = _offset;
			if ((_seed % 10000) == 0)
			{
				std::cout << "Rand: " << _seed << std::endl;
			}
			++_seed;
		}

		return _key;
	}
	virtual bool Done() override
	{
		if (_maxSeed == std::numeric_limits<uint32_t>::max())
		{
			return _seed == _maxSeed;
		}
		return _seed >= _maxSeed;
	}
};

template <typename TIter>
void LoadHashes(std::istream& is, TIter out)
{
	bc::data_chunk hash;
	std::istream_iterator<std::string> const end;
	for (auto i = std::istream_iterator<std::string>(is); i != end; ++i)
	{
		auto const line = boost::regex_replace(*i, CommentPattern, "", boost::format_all);

		if (line.empty())
		{
			continue;
		}
		if (!bc::decode_base16(hash, line))
		{
			std::cerr << "Failed to decode: " << line << std::endl;
			continue;
		}
		*out++ = hash;
	}
}

template <typename TIter>
void LoadAddressHashes(std::istream& is, TIter out)
{
	uint8_t version;
	uint32_t checksum;
	bc::data_chunk decoded_address;
	bc::data_chunk payload;

	std::istream_iterator<std::string> const end;
	for (auto i = std::istream_iterator<std::string>(is); i != end; ++i)
	{
		auto const line = boost::regex_replace(*i, CommentPattern, "", boost::format_all);

		if (line.empty())
		{
			continue;
		}
		if (!bc::decode_base58(decoded_address, line))
		{
			std::cerr << "Failed to decode: " << line << std::endl;
			continue;
		}
		if (!bc::unwrap(version, payload, checksum, decoded_address))
		{
			std::cerr << "Failed to unwrap: " << line << std::endl;
			continue;
		}
		*out++ = payload;
	}
}

static inline void short_hash(bc::ec_point const& ecp,
	bc::hash_digest& sha, bc::short_hash& rmd,
	RMD160CTX& rmdctx, SHA256CTX& shactx)
{
	SHA256Init(&shactx);
	SHA256Update(&shactx, ecp.data(), ecp.size());
	SHA256Final(&shactx, sha.data());
	RMD160Init(&rmdctx);
	RMD160Update(&rmdctx, sha.data(), sha.size());
	RMD160Final(&rmdctx, rmd.data());
}

void Check(SecretGenerator* gen, std::function<bool(uint8_t const* p, size_t n)> f, uint64_t maxIter = 0)
{
	RMD160CTX rmd160ctx;
	SHA256CTX sha256ctx;
	bc::short_hash shortHash;
	bc::hash_digest hashDigest;
	bc::ec_point compressed_pub_ecp(bc::ec_compressed_size);
	bc::ec_point uncompressed_pub_ecp(bc::ec_uncompressed_size);
	bc::payment_address addr;

	for (uint64_t i = 0; !gen->Done() && (i < maxIter || !maxIter); ++i)
	{
		auto k = gen->Next();
		bool match = false;

		//std::cout << "Private Key: " << bc::secret_to_wif(k, true) << std::endl;

		int out_size;
		if (secp256k1_ec_pubkey_create(compressed_pub_ecp.data(), &out_size, k.data(), true) == 1 &&
			out_size == bc::ec_compressed_size)
		{
			short_hash(compressed_pub_ecp, hashDigest, shortHash, rmd160ctx, sha256ctx);
			if (f(shortHash.data(), shortHash.size()))
			{
				match = true;
				bc::set_public_key(addr, compressed_pub_ecp);
			}
		}
		else
		{
			std::cerr << "secp256k1_ec_pubkey_create(C) failed (" << out_size << ")" << std::endl;
		}

		if (secp256k1_ec_pubkey_create(uncompressed_pub_ecp.data(), &out_size, k.data(), false) == 1 &&
			out_size == bc::ec_uncompressed_size)
		{
			short_hash(uncompressed_pub_ecp, hashDigest, shortHash, rmd160ctx, sha256ctx);
			if (f(shortHash.data(), shortHash.size()))
			{
				match = true;
				bc::set_public_key(addr, uncompressed_pub_ecp);
			}
		}
		else
		{
			std::cerr << "secp256k1_ec_pubkey_create(U) failed (" << out_size << ")" << std::endl;
		}

		if (match)
		{
			std::cout << "Match!" << std::endl
			   << "Address:     " << addr.encoded() << std::endl
			   << "Private Key: " << bc::secret_to_wif(k, true) << std::endl;
		}
	}
}

class Inserter
{
	std::vector<uint8_t>& _v;
public:
	Inserter(std::vector<uint8_t>& v) : _v(v) {}
	Inserter& operator=(std::vector<uint8_t> const& rhs) 
	{
		_v.insert(_v.end(), rhs.begin(), rhs.end());
		return *this;
	}
	Inserter& operator*() { return *this; }
	Inserter& operator++() { return *this; }
	Inserter& operator++(int) { return *this; }
};

int main(int /*argc*/, char* /*argv*/[])
{
	secp256k1_start(SECP256K1_START_VERIFY | SECP256K1_START_SIGN);

	//char const* const fileName = "addrs.txt";
	char const* const fileName = "hashes.txt";
	std::ifstream file;
	file.open(fileName);
	if (!file.is_open())
	{
		std::cerr << "Error: Failed to open file" << std::endl;
		return 1;
	}

	typedef std::chrono::steady_clock::time_point time_point;
	typedef std::chrono::duration<double> time_duration;
	time_point t0, t1;
	time_duration duration;

	t0 = std::chrono::steady_clock::now();
	std::set<bc::data_chunk> addrs;
	//LoadAddressHashes(file, std::inserter(addrs, addrs.end()));
	LoadHashes(file, std::inserter(addrs, addrs.end()));
	t1 = std::chrono::steady_clock::now();
	duration = std::chrono::duration_cast<time_duration>(t1 - t0);
	std::cout << "Loaded " << addrs.size()
		<< " address hashes in " << duration.count() << "s" << std::endl;

	file.close();
	auto const addrFileSize = bfs::file_size(fileName);
	file.open(fileName);

	t0 = std::chrono::steady_clock::now();
	std::vector<bc::data_chunk> chunks;
	auto const estimatedAddrCount = addrFileSize / 34;
	chunks.reserve(estimatedAddrCount);
	//LoadAddressHashes(file, std::back_inserter(chunks));
	LoadHashes(file, std::back_inserter(chunks));
	std::sort(chunks.begin(), chunks.end());
	t1 = std::chrono::steady_clock::now();
	duration = std::chrono::duration_cast<time_duration>(t1 - t0);
	std::cout << "Loaded " << chunks.size()
		<< " address hashes in " << duration.count() << "s" << std::endl;

	file.close();
	file.open(fileName);

	t0 = std::chrono::steady_clock::now();
	std::vector<uint8_t> chunkdata;
	chunks.reserve(estimatedAddrCount * bc::short_hash_size);
	//LoadAddressHashes(file, Inserter(chunkdata));
	LoadHashes(file, Inserter(chunkdata));
	t1 = std::chrono::steady_clock::now();
	duration = std::chrono::duration_cast<time_duration>(t1 - t0);
	std::cout << "Loaded " << chunkdata.size()/bc::short_hash_size
		<< " address hashes in " << duration.count() << "s" << std::endl;

	bloom_parameters parameters;
	parameters.projected_element_count    = addrs.size();
	parameters.false_positive_probability = 1.0 / 100000000;
	parameters.random_seed                = 0xA5A5A5A5;
	
	if (!parameters)
	{
		std::cerr << "Error: Invalid Bloom filter parameters" << std::endl;
		return 1;
	}
	
	parameters.compute_optimal_parameters();

	std::cout << "Bloom Filter Parameters:" << std::endl
		<< "Projected Count: " << parameters.projected_element_count << std::endl
		<< "Probabililty:    " << parameters.false_positive_probability << std::endl
		<< "Hashes:          " << parameters.optimal_parameters.number_of_hashes << std::endl
		<< "Table Size:      " << parameters.optimal_parameters.table_size << std::endl;

	bloom_filter addrFilter(parameters);

	// add hashes to bloom filter
	for_each(addrs.begin(), addrs.end(),
		[&addrFilter](bc::data_chunk const& addr) {
			addrFilter.insert(addr.data(), addr.size()); });

	struct tm timeinfo;
	timeinfo.tm_year = 2010 - 1900;
	timeinfo.tm_mon = 0;
	timeinfo.tm_mday = 1;
	timeinfo.tm_hour = 0;
	timeinfo.tm_min = 0;
	timeinfo.tm_sec = 0;
	auto const seed = timegm(&timeinfo);
	auto const maxSeed = time(NULL);

	auto const warmup = 10000;
	auto const iter = 100000;

	Check(new SerialSecretGenerator(),
		[&addrs](uint8_t const* p, size_t n) -> bool {
			return addrs.find(bc::data_chunk(p, p+n)) != addrs.end();
		},
		warmup);
	t0 = std::chrono::steady_clock::now();
	Check(new SerialSecretGenerator(),
		[&addrs](uint8_t const* p, size_t n) -> bool {
			return addrs.find(bc::data_chunk(p, p+n)) != addrs.end();
		},
		iter);
	t1 = std::chrono::steady_clock::now();
	duration = std::chrono::duration_cast<std::chrono::duration<double> >(t1 - t0);
	std::cout << "Set: " << duration.count() << "s" << std::endl;


	Check(new SerialSecretGenerator(),
		[&chunks](uint8_t const* p, size_t n) -> bool {
			return std::binary_search(chunks.begin(), chunks.end(), bc::data_chunk(p, p+n));
		},
		warmup);
	t0 = std::chrono::steady_clock::now();
	Check(new SerialSecretGenerator(),
		[&chunks](uint8_t const* p, size_t n) -> bool {
			return std::binary_search(chunks.begin(), chunks.end(), bc::data_chunk(p, p+n));
		},
		iter);
	t1 = std::chrono::steady_clock::now();
	duration = std::chrono::duration_cast<std::chrono::duration<double> >(t1 - t0);
	std::cout << "Vector: " << duration.count() << "s" << std::endl;

	Check(new SerialSecretGenerator(),
		[&addrFilter](uint8_t const* p, size_t n) -> bool { return addrFilter.contains(p,n); },
		warmup);
	t0 = std::chrono::steady_clock::now();
	Check(new SerialSecretGenerator(),
		[&addrFilter](uint8_t const* p, size_t n) -> bool { return addrFilter.contains(p,n); },
		iter);
	t1 = std::chrono::steady_clock::now();
	duration = std::chrono::duration_cast<std::chrono::duration<double> >(t1 - t0);
	std::cout << "Bloom Filter: " << duration.count() << "s" << std::endl;

/*
	std::unique_ptr<SecretGenerator> gen(new RandSecretGenerator(seed, maxSeed, 0, 20));

	t0 = std::chrono::steady_clock::now();
	Check(gen.get(), [&addrFilter](uint8_t const* p, size_t n) -> bool { return addrFilter.contains(p,n); });
	t1 = std::chrono::steady_clock::now();
	duration = std::chrono::duration_cast<std::chrono::duration<double> >(t1 - t0);
	std::cout << duration.count() << "s" << std::endl;
*/
	return 0;
}

