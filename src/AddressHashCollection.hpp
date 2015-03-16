#ifndef ADDRESS_HASH_COLLECTION_HPP
#define ADDRESS_HASH_COLLECTION_HPP

#include <bitcoin/bitcoin.hpp>
#include <bloom_filter.hpp>
#include <memory>
#include <string>
#include <vector>


class AddressHashCollection
{
public:
	AddressHashCollection(size_t approxHashCount)
	{
		_hashes.reserve(approxHashCount);
	}

	size_t GetCount() const { return _hashes.size(); }

	bool AddAddress(std::string const& str)
	{
		uint8_t version;
		uint32_t checksum;
		bc::data_chunk decoded_address;
		bc::short_hash payload;

		return bc::decode_base58(decoded_address, str) &&
			bc::unwrap(version, payload, checksum, decoded_address) &&
			AddHash(payload);
	}

	bool AddHash(std::string const& str)
	{
		bc::short_hash hash;
		return bc::decode_base16(hash, str) && AddHash(hash);
	}

	bool AddHash(bc::short_hash const& hash)
	{
		_hashes.push_back(hash);
		return true;
	}

	bool Build()
	{
		std::sort(_hashes.begin(), _hashes.end());

		bloom_parameters parameters;
		parameters.projected_element_count    = _hashes.size();
		parameters.false_positive_probability = 1.0 / 1000;
		parameters.random_seed                = 0xA5A5A5A5A5A5A5A5ULL;
		
		if (!parameters)
		{
			std::cerr << "Error: Invalid Bloom filter parameters" << std::endl;
			return false;
		}
	
		parameters.compute_optimal_parameters();
		parameters.optimal_parameters.table_size *= 5;
		/*
		std::cout << "Bloom Filter Parameters:" << std::endl
			<< "Probabililty:    " << parameters.false_positive_probability << std::endl
			<< "Hashes:          " << parameters.optimal_parameters.number_of_hashes << std::endl
			<< "Table Size:      " << parameters.optimal_parameters.table_size << std::endl;
		*/
		_filter = std::unique_ptr<bloom_filter>(new bloom_filter(parameters));

		for_each(_hashes.begin(), _hashes.end(),
			[this](bc::short_hash const& hash) { this->_filter->insert(hash.data(), hash.size() / 2); });

		return true;
	}

	bool ProbablyContains(bc::short_hash const& hash) const
	{
		return _filter->contains(hash.data(), hash.size() / 2);
	}

	bool Contains(bc::short_hash const& hash) const
	{
		return std::binary_search(_hashes.begin(), _hashes.end(), hash);
	}

private:
	std::vector<bc::short_hash> _hashes;
	std::unique_ptr<bloom_filter> _filter;
};

#endif

