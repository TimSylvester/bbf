#include "RandSecretGenerator.hpp"

#include <bitcoin/bitcoin.hpp>

#include <boost/date_time.hpp>
#include <boost/optional.hpp>

#include <tclap/CmdLine.h>

#include <iostream>
#include <string>

namespace bpt = boost::posix_time;

static std::locale const dateTimeFormats[] = {
	std::locale(std::locale::classic(), new bpt::time_input_facet("%Y-%m-%d %H:%M:%S")),
	std::locale(std::locale::classic(), new bpt::time_input_facet("%Y/%m/%d %H:%M:%S")),
	std::locale(std::locale::classic(), new bpt::time_input_facet("%d.%m.%Y %H:%M:%S")),
	std::locale(std::locale::classic(), new bpt::time_input_facet("%Y-%m-%dT%H:%M:%S")),
	std::locale(std::locale::classic(), new bpt::time_input_facet("%Y/%m/%dT%H:%M:%S")),
	std::locale(std::locale::classic(), new bpt::time_input_facet("%d.%m.%YT%H:%M:%S")),
	std::locale(std::locale::classic(), new bpt::time_input_facet("%Y-%m-%d")),
	std::locale(std::locale::classic(), new bpt::time_input_facet("%Y/%m/%d")),
};
static auto const dateTimeFormatCount = sizeof(dateTimeFormats)/sizeof(dateTimeFormats[0]);

static bpt::ptime unix_epoch_time(boost::gregorian::date(1970,1,1));
static std::time_t to_time_t(const bpt::ptime& pt)
{
	auto diff = pt - unix_epoch_time;
	return (std::time_t)(diff.ticks() / diff.ticks_per_second());
}
static boost::optional<time_t> to_time_t(boost::optional<bpt::ptime> const& pt)
{
	return pt ? to_time_t(*pt) : boost::optional<time_t>();
}

static boost::optional<bpt::ptime> ParseDateTime(const std::string& s)
{
	bpt::ptime pt;
	for (size_t i = 0; i < dateTimeFormatCount; ++i)
	{
		std::istringstream is(s);
		is.imbue(dateTimeFormats[i]);
		is >> pt;
		if(pt != bpt::ptime())
		{
			return pt;
		}
	}
	return boost::optional<bpt::ptime>();
}

int main(int argc, char* argv[])
{
	TCLAP::CmdLine cmd("RandSecretGenerator", ' ', "0.1");
	TCLAP::ValueArg<unsigned> minSeedArg("", "minseed",
		"Minimum seed value", false, 1262304000, "uint32", cmd);
	TCLAP::ValueArg<unsigned> maxSeedArg("", "maxseed",
		"Maximum seed value", false, 1262304000, "uint32", cmd);
	TCLAP::ValueArg<std::string> minTimeArg("", "mintime",
		"Minimum time value", false, std::string(), "string", cmd);
	TCLAP::ValueArg<std::string> maxTimeArg("", "maxtime",
		"Maximum time value", false, std::string(), "string", cmd);
	TCLAP::ValueArg<unsigned> minOffsetArg("", "minoffset",
		"Minimum rand() offset", false, 0, "uint32", cmd);
	TCLAP::ValueArg<unsigned> maxOffsetArg("", "maxoffset",
		"Maximum rand() offset", false, 0, "uint32", cmd);
	TCLAP::ValueArg<uint64_t> maxKeysArg("", "limit",
		"Maximum number of keys to generate", false, 0, "uint64", cmd);

	try
	{
		cmd.parse(argc, argv);
	}
	catch (TCLAP::ArgException const& e)
	{
		std::cerr << "Error: " << e.error() << " for arg " << e.argId() << std::endl;
		return 1;
	}

	auto minSeed = minSeedArg.getValue();
	auto maxSeed = maxSeedArg.getValue();
	if (!minTimeArg.getValue().empty())
	{
		if (auto t = to_time_t(ParseDateTime(minTimeArg.getValue())))
		{
			minSeed = (int32_t)*t;
		}
	}
	if (!maxTimeArg.getValue().empty())
	{
		if (auto t = to_time_t(ParseDateTime(maxTimeArg.getValue())))
		{
			maxSeed = (int32_t)*t;
		}
	}

	auto gen = std::unique_ptr<SecretGenerator>(
		new RandSecretGenerator(
			minSeed, maxSeed,
			minOffsetArg.getValue(),
			maxOffsetArg.getValue()));

	auto const keyLimit = maxKeysArg.getValue();

	bc::ec_secret secret;
	for (uint64_t i = 0; !gen->Done() && (keyLimit == 0 || i < keyLimit); ++i)
	{
		secret = gen->Next();
		std::cout << bc::encode_base16(secret) << std::endl;
	}

	return 0;
}

