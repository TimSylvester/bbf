#include <bitcoin/bitcoin.hpp>
#include <bitcoin/bitcoin/math/external/sha256.h>

#include <tclap/CmdLine.h>

#include <iostream>
#include <string>

// character classifier in which only newlines are whitespace
class line_classifier : public std::ctype<char>
{
public:
	typedef std::ctype_base::mask mask;
	line_classifier() : std::ctype<char>(get_table()) {}
private:
	static mask const* get_table()
	{
		static std::vector<mask> rc(table_size, mask());
		rc['\r'] = rc['\n'] = std::ctype_base::space;
		return &rc[0];
	}
};

int main(int argc, char* argv[])
{
	TCLAP::CmdLine cmd("Sha2Generator", ' ', "0.1");
	TCLAP::UnlabeledValueArg<std::string> inputFileArg("input",
		"Input File", false, std::string(), "string", cmd);
	TCLAP::ValueArg<std::string> outputFileArg("o", "output",
		"Output File", false, std::string(), "string", cmd);
	TCLAP::SwitchArg byWordArg("", "words", "Read by word instead of by line", cmd);
	TCLAP::SwitchArg base16Arg("", "base-16", "Base-16 Output", false);
	TCLAP::SwitchArg base58Arg("", "base-58", "Base-58 Output", false);
	TCLAP::SwitchArg base64Arg("", "base-64", "Base-64 Output", false);
	TCLAP::SwitchArg base85Arg("", "base-85", "Base-85 Output", false);
	try
	{
		// xorAdd doesn't work correctly with default-true parameters
		cmd.add(base16Arg);
		cmd.add(base58Arg);
		cmd.add(base64Arg);
		cmd.add(base85Arg);
		//std::vector<TCLAP::Arg*> formats = { &base16Arg, &base58Arg, &base64Arg };
		//cmd.xorAdd(formats);

		cmd.parse(argc, argv);
	}
	catch (TCLAP::ArgException const& e)
	{
		std::cerr << "Error: " << e.error() << " for arg " << e.argId() << std::endl;
		return 1;
	}

	auto const& inputFileName = inputFileArg.getValue();
	auto const& outputFileName = outputFileArg.getValue();
	auto const base58 = base58Arg.getValue();	// use isSet with xorAdd
	auto const base64 = base64Arg.getValue();
	auto const base85 = base85Arg.getValue();
	auto const base16 = base16Arg.getValue() || (!base58 && !base64 && !base85);

	if ((base16?1:0)+(base58?1:0)+(base64?1:0)+(base85?1:0) != 1)
	{
		std::cerr << "Only one --base-NN output format option may be set" << std::endl;
		return 1;
	}

	std::ifstream inputFile;
	std::istream* inputStreamPtr;
	if (inputFileName.empty() || inputFileName == "-")
	{
		inputStreamPtr = &std::cin;
	}
	else
	{
		inputFile.open(inputFileName);
		if (!inputFile.is_open())
		{
			std::cerr << "Error: Failed to open " << inputFileName << std::endl;
			return 1;
		}
		inputStreamPtr = &inputFile;
	}
	auto& inputStream = *inputStreamPtr;

	std::ofstream outputFile;
	std::ostream* outputStreamPtr;
	if (outputFileName.empty() || outputFileName == "-")
	{
		outputStreamPtr = &std::cout;
	}
	else
	{
		outputFile.open(outputFileName);
		if (!outputFile.is_open())
		{
			std::cerr << "Error: Failed to open " << outputFileName << std::endl;
			return 1;
		}
		outputStreamPtr = &outputFile;
	}
	auto& outputStream = *outputStreamPtr;

	if (!byWordArg.getValue())
	{
		inputStream.imbue(std::locale(std::locale(), new line_classifier()));
	}

	SHA256CTX shactx;
	bc::hash_digest sha;
	std::string tempStr;

	std::istream_iterator<std::string> const end;
	for (auto i = std::istream_iterator<std::string>(inputStream); i != end; ++i)
	{
		auto const& line = *i;

		SHA256Init(&shactx);
		SHA256Update(&shactx, (uint8_t const*)line.c_str(), line.length());
		SHA256Final(&shactx, sha.data());

		if      (base16) outputStream << bc::encode_base16(sha);
		else if (base58) outputStream << bc::encode_base58(sha);
		else if (base64) outputStream << bc::encode_base64(sha);
		else if (base85) { bc::encode_base85(tempStr, sha); outputStream << tempStr; }
		else             outputStream << "inconceivable!";

		outputStream << std::endl;
	}

	return 0;
}

