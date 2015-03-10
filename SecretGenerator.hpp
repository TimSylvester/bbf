#ifndef SECRET_GENERATOR_HPP
#define SECRET_GENERATOR_HPP

#include <bitcoin/bitcoin.hpp>

class SecretGenerator
{
public:
	SecretGenerator() {}
	virtual ~SecretGenerator() {}
	virtual bc::ec_secret const& Next() = 0;
	virtual std::string Print() = 0;
	virtual bool Done() = 0;
};

#endif
