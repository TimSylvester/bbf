#ifndef SERIAL_SECRET_GENERATOR_HPP
#define SERIAL_SECRET_GENERATOR_HPP

#include "SecretGenerator.hpp"

class SerialSecretGenerator
	: public SecretGenerator
{
private:
	bc::ec_secret	_key;

	static const constexpr bc::ec_secret KeyZero = {{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

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

	virtual std::string Print() override
	{
		return bc::encode_base16(_key);
	}

	virtual bool Done() override
	{
		return false;
	}
};

#endif

