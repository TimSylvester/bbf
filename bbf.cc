#include "AddressHashCollection.hpp"
#include "SerialSecretGenerator.hpp"
#include "RandSecretGenerator.hpp"

#include <secp256k1.h>
#include <bitcoin/bitcoin.hpp>
#include <bitcoin/bitcoin/math/external/ripemd160.h>
#include <bitcoin/bitcoin/math/external/sha256.h>
#include <bloom_filter.hpp>
#include <boost/filesystem.hpp>
#include <boost/range/counting_range.hpp>
#include <boost/regex.hpp>
#include <boost/thread.hpp>
#include <tclap/CmdLine.h>
#include <algorithm>
#include <chrono>
#include <functional>
#include <future>
#include <set>
#include <string>
#include <thread>

namespace bfs = boost::filesystem;
static const boost::regex CommentPattern("^\\s*|\\s*$");

typedef std::function<bool(bc::ec_secret&)> GetSecretFn;

typedef boost::mutex lock_type;
typedef lock_type::scoped_lock guard_type;

static inline void get_short_hash(bc::ec_point const& ecp,
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

uint64_t Check(GetSecretFn getSecret, AddressHashCollection const& addrs)
{
	RMD160CTX rmd160ctx;
	SHA256CTX sha256ctx;
	bc::short_hash shortHash;
	bc::hash_digest hashDigest;
	bc::ec_point compressed_pub_ecp(bc::ec_compressed_size);
	bc::ec_point uncompressed_pub_ecp(bc::ec_uncompressed_size);
	bc::payment_address addr;
	bc::ec_secret secret;

	auto checked = 0ULL;
	while (getSecret(secret))
	{
		bool match = false;

		int out_size;
		if (secp256k1_ec_pubkey_create(compressed_pub_ecp.data(), &out_size, secret.data(), true) == 1 &&
			out_size == bc::ec_compressed_size)
		{
			get_short_hash(compressed_pub_ecp, hashDigest, shortHash, rmd160ctx, sha256ctx);
			if (addrs.ProbablyContains(shortHash) && addrs.Contains(shortHash))
			{
				match = true;
				bc::set_public_key(addr, compressed_pub_ecp);
			}
			++checked;
		}
		else
		{
			std::cerr << "secp256k1_ec_pubkey_create(C) failed (" << out_size << ")" << std::endl;
		}

		if (secp256k1_ec_pubkey_create(uncompressed_pub_ecp.data(), &out_size, secret.data(), false) == 1 &&
			out_size == bc::ec_uncompressed_size)
		{
			get_short_hash(uncompressed_pub_ecp, hashDigest, shortHash, rmd160ctx, sha256ctx);
			if (addrs.ProbablyContains(shortHash) && addrs.Contains(shortHash))
			{
				match = true;
				bc::set_public_key(addr, uncompressed_pub_ecp);
			}
			++checked;
		}
		else
		{
			std::cerr << "secp256k1_ec_pubkey_create(U) failed (" << out_size << ")" << std::endl;
		}

		if (match)
		{
			std::cout << "Match!" << std::endl
			   << "Address:     " << addr.encoded() << std::endl
			   << "Private Key: " << bc::secret_to_wif(secret, true) << std::endl;
		}
	}
	return checked;
}

uint64_t TimedCheck(GetSecretFn getSecret, AddressHashCollection const& addrs)
{
	auto const t0 = std::chrono::steady_clock::now();
	auto const checked = Check(getSecret, addrs);
	auto const t1 = std::chrono::steady_clock::now();
	auto const duration = std::chrono::duration_cast<std::chrono::duration<double> >(t1 - t0);
	std::cerr << "Checked " << checked <<  " in " << duration.count() << "s ("
		<< (checked / duration.count()) << "/s)" << std::endl;
	return checked;
}

static unsigned DefaultThreadCount()
{
	auto cores = std::thread::hardware_concurrency();
	return cores ? cores : 1;
}
static unsigned MaxThreadCount()
{
	return DefaultThreadCount() * 10;
}

int main(int argc, char* argv[])
{
	TCLAP::CmdLine cmd("BBF", ' ', "0.1");
	TCLAP::UnlabeledValueArg<std::string> hashFileArg("hashFile",
		"File containing base-16 hash strings", true, std::string(), "string", cmd);
	TCLAP::ValueArg<unsigned> threadCountArg("j", "threadCount",
		"Number of threads to use", false, DefaultThreadCount(), "int", cmd);
	try
	{
		cmd.parse(argc, argv);
	}
	catch (TCLAP::ArgException const& e)
	{
		std::cerr << "Error: " << e.error() << " for arg " << e.argId() << std::endl;
		return 1;
	}

	auto const& fileName = hashFileArg.getValue();
	auto const threadCount = std::max(1U, std::min(MaxThreadCount(), threadCountArg.getValue()));

	std::ifstream file;
	std::istream* inputStreamPtr;
	uint64_t estimatedSize;
	if (fileName == "-")
	{
		inputStreamPtr = &std::cin;
		estimatedSize = 100 * 1024;
	}
	else
	{
		file.open(fileName);
		if (!file.is_open())
		{
			std::cerr << "Error: Failed to open " << fileName << std::endl;
			return 1;
		}
		inputStreamPtr = &file;
		estimatedSize = bfs::file_size(fileName);
	}
	std::istream& inputStream = *inputStreamPtr;

	secp256k1_start(SECP256K1_START_VERIFY | SECP256K1_START_SIGN);

	auto const estimatedHashCount = estimatedSize / 41;	// 34
	AddressHashCollection addrs(estimatedHashCount);

	std::istream_iterator<std::string> const end;
	for (auto i = std::istream_iterator<std::string>(inputStream); i != end; ++i)
	{
		auto const& line = *i;
		if (!line.empty() && !addrs.AddHash(line))
		{
			std::cerr << "Bad hash ignored: " << line << std::endl;
		}
	}

	if (!addrs.Build())
	{
		std::cerr << "Failed to initialize address collection" << std::endl;
		return 1;
	}

	std::cout << "Loaded " << addrs.GetCount() << " address hashes" << std::endl;

	struct tm timeinfo;
	timeinfo.tm_year = 2010 - 1900;
	timeinfo.tm_mon = 0;
	timeinfo.tm_mday = 1;
	timeinfo.tm_hour = 0;
	timeinfo.tm_min = 0;
	timeinfo.tm_sec = 0;
	auto const minSeed = timegm(&timeinfo);

	//timeinfo.tm_year = 2016;
	timeinfo.tm_mday = 2;
	auto const maxSeed = timegm(&timeinfo);

	lock_type lock;
	auto gen = std::unique_ptr<SecretGenerator>(new RandSecretGenerator(minSeed, maxSeed, 0, 10));
	auto f = [&](bc::ec_secret& secret){
			guard_type guard(lock);
			secret = gen->Next();
			return !gen->Done();
		};

	std::vector<std::future<uint64_t>> results;
	for (auto i : boost::counting_range(0U, threadCount))
	{
		results.push_back(std::async(std::launch::async, [&]{ return TimedCheck(f, addrs); }));
	}
	for (auto& result : results)
	{
		auto count = result.get();
		std::cerr << "Result: " << count << std::endl;
	}

	return 0;
}

