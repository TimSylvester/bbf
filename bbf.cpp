#include "AddressHashCollection.hpp"
#include "concurrent_queue.hpp"

#include <secp256k1.h>
#include <bitcoin/bitcoin.hpp>
#include <bitcoin/bitcoin/math/external/ripemd160.h>
#include <bitcoin/bitcoin/math/external/sha256.h>
#include <bloom_filter.hpp>
#include <boost/filesystem.hpp>
#include <boost/range/counting_range.hpp>
#include <boost/regex.hpp>
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

typedef std::mutex lock_type;
typedef std::unique_lock<lock_type> guard_type;

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
	secp256k1_start(SECP256K1_START_VERIFY | SECP256K1_START_SIGN);

	TCLAP::CmdLine cmd("BBF", ' ', "0.1");
	TCLAP::UnlabeledValueArg<std::string> keyFileArg("keyfile",
		"File containing base-16 keys", false, "-", "string", cmd);
	TCLAP::ValueArg<std::string> hashFileArg("a", "hashfile",
		"File containing base-16 address hashes", true, std::string(), "string", cmd);
	TCLAP::ValueArg<unsigned> threadCountArg("j", "threads",
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

	auto const& hashFileName = hashFileArg.getValue();
	auto const& keyFileName = keyFileArg.getValue();
	auto const threadCount = std::max(1U, std::min(MaxThreadCount(), threadCountArg.getValue()));

	if (hashFileName == keyFileName)
	{
		std::cerr << "Error: Address hash and key sources match" << std::endl;
		return 1;
	}

	std::ifstream hashFile;
	std::istream* hashStreamPtr;
	uint64_t estimatedSize;
	if (hashFileName == "-")
	{
		hashStreamPtr = &std::cin;
		estimatedSize = 100 * 1024;
	}
	else
	{
		hashFile.open(hashFileName);
		if (!hashFile.is_open())
		{
			std::cerr << "Error: Failed to open " << hashFileName << std::endl;
			return 1;
		}
		hashStreamPtr = &hashFile;
		estimatedSize = bfs::file_size(hashFileName);
	}
	std::istream& hashStream = *hashStreamPtr;

	std::ifstream keyFile;
	std::istream* keyStreamPtr;
	if (keyFileName == "-")
	{
		keyStreamPtr = &std::cin;
	}
	else
	{
		keyFile.open(keyFileName);
		if (!keyFile.is_open())
		{
			std::cerr << "Error: Failed to open " << keyFileName << std::endl;
			return 1;
		}
		keyStreamPtr = &keyFile;
	}
	std::istream& keyStream = *keyStreamPtr;

	auto const estimatedHashCount = estimatedSize / 41;	// 34
	AddressHashCollection addrs(estimatedHashCount);

	std::istream_iterator<std::string> const end;
	for (auto i = std::istream_iterator<std::string>(hashStream); i != end; ++i)
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

	concurrent_queue<bc::ec_secret> queue(1000U);
	std::atomic<bool> done(false);

	auto loadKeys = [&] {
			std::istream_iterator<std::string> const end;
			bc::ec_secret secret;
			for (auto i = std::istream_iterator<std::string>(keyStream); i != end && !done; ++i)
			{
				auto const& line = *i;
				if (!bc::decode_base16(secret, line))
				{
					std::cerr << "Bad hash ignored: " << line << std::endl;
					continue;
				}
				if (!queue.push(secret, std::chrono::seconds(30)))
				{
					std::cerr << "load failed" << std::endl;
					break;
				}
			}
			std::cerr << "load complete" << std::endl;
			done = true;
		};
	auto getKey = [&](bc::ec_secret& secret) {
			while (!done) {
				if (!queue.pop(secret, std::chrono::seconds(30))) {
					std::cerr << "pop failed" << std::endl;
					return false;
				}
				return true;
			}
			return false;
		};

	std::thread loader(loadKeys);

	std::vector<std::future<uint64_t>> results;
	for (auto i : boost::counting_range(0U, threadCount))
	{
		results.push_back(std::async(std::launch::async, [&]{ return TimedCheck(getKey, addrs); }));
	}
	for (auto& result : results)
	{
		auto count = result.get();
		std::cerr << "Result: " << count << std::endl;
	}

	done = true;
	queue.stop();
	loader.join();

	return 0;
}

