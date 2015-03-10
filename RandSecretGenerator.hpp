#ifndef RAND_SECRET_GENERATOR_HPP
#define RAND_SECRET_GENERATOR_HPP

#include "SecretGenerator.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/format.hpp>

class RandSecretGenerator
	: public SecretGenerator
{
private:
	bc::ec_secret   _key;
	uint32_t        _seed;
	uint32_t        _maxSeed;
	int             _minOffset;
	int             _curOffset;
	int             _maxOffset;
	int             _bytes;

public:
	RandSecretGenerator(
			uint32_t minSeed = 0, uint32_t maxSeed = 0,
			int minOffset = 0, int maxOffset = 0)
		: _seed      (minSeed)
		, _maxSeed   (maxSeed)
		, _minOffset (minOffset)
		, _curOffset (minOffset)
		, _maxOffset (maxOffset)
		, _bytes     (1)
	{
	}

	virtual std::string Print() override
	{
		static std::locale loc(std::cout.getloc(), new boost::posix_time::time_facet("%Y-%m-%d %H:%M:%S"));
		std::stringstream ss;
		ss.imbue(loc);
		ss << (boost::posix_time::from_time_t(_seed));
		return boost::str(boost::format("seed=%s offset=%d w=%d") %ss.str() %_curOffset %_bytes);
	}

	virtual void RandFill()
	{
		if (_bytes == 4)
		{
			int const chunkCount = _key.size()/sizeof(uint32_t);
			auto p = (uint32_t*)_key.data();
			for (int i = 0; i < chunkCount; ++i)
			{
				*p++ = rand();
			}
		}
		else if (_bytes == 1)
		{
			int const chunkCount = _key.size()/sizeof(uint8_t);
			auto p = (uint8_t*)_key.data();
			for (int i = 0; i < chunkCount; ++i)
			{
				*p++ = (uint8_t)rand();
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

		if (_bytes == 1)
		{
			_bytes = 4;
		}
		else if (_minOffset < _maxOffset && _curOffset < _maxOffset)
		{
			_bytes = 1;
			++_curOffset;
		}
		else
		{
			_bytes = 1;
			_curOffset = _minOffset;
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
		return _seed > _maxSeed;
	}
};

#endif

