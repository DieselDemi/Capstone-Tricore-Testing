#include <iostream> 
#include <stdio.h> 
#include <inttypes.h> 
#include <string> 
#include <fstream> 
#include <vector> 

#include <capstone/capstone.h> 
#include <pe-parse/parse.h> 

using ParsedPeRef = std::unique_ptr<peparse::parsed_pe, void(*)(peparse::parsed_pe*)>; 

ParsedPeRef open_exe(const std::string& path) noexcept 
{
	ParsedPeRef obj(peparse::ParsePEFromFile(path.data()), peparse::DestructParsedPE);
	if(!obj) { 
		return ParsedPeRef(nullptr, peparse::DestructParsedPE); 

	}
	
	return obj; 
}

enum class AddressType 
{ 
	PhysicalOffset, 
	RelativeVirtualAddress, //RVA
	VirtualAddress //VA
};

bool convertAddress(ParsedPeRef &pe, 
		     std::uint64_t address, 
		     AddressType source_type, 
		     AddressType destination_type, 
		     std::uint64_t &result) noexcept 
{ 
	if(source_type == destination_type) { 
		result = address; 
		return true; 
	}

	std::uint64_t image_base_address = 0U; 

	if(pe->peHeader.nt.FileHeader.Machine == peparse::IMAGE_FILE_MACHINE_AMD64) { 
		image_base_address = pe->peHeader.nt.OptionalHeader64.ImageBase; 
	} else { 
		image_base_address = pe->peHeader.nt.OptionalHeader.ImageBase; 
	}

	
	struct SectionAddressLimits final { 
		std::uintptr_t lowest_rva; 
		std::uintptr_t lowest_offset; 
		std::uintptr_t highest_rva; 
		std::uintptr_t highest_offset; 
	};

	auto L_getSectionAddressLimits = [](
			void*N, 
			const peparse::VA &secBase, 
			const std::string &secName, 
			const peparse::image_section_header &s, 
			const peparse::bounded_buffer *data) -> int 
	{ 
		static_cast<void>(secBase); 
		static_cast<void>(secName); 
		static_cast<void>(data); 

		SectionAddressLimits *section_address_limits = 
			static_cast<SectionAddressLimits *>(N); 

		section_address_limits->lowest_rva =
		       std::min(section_address_limits->lowest_rva, 
				       static_cast<std::uintptr_t>(s.VirtualAddress)); 

		section_address_limits->lowest_offset =
			std::min(section_address_limits->lowest_offset, 
					static_cast<std::uintptr_t>(s.PointerToRawData)); 

		std::uintptr_t sectionSize; 

		if(s.SizeOfRawData != 0){ 

			sectionSize = s.SizeOfRawData; 
		} else { 
			sectionSize = s.Misc.VirtualSize; 
		}

		section_address_limits->highest_rva = 
			std::max(section_address_limits->highest_rva, 
					static_cast<std::uintptr_t>(s.VirtualAddress + sectionSize)); 

		section_address_limits->highest_offset =
			std::max(section_address_limits->highest_offset, 
					static_cast<std::uintptr_t>(s.PointerToRawData + sectionSize)); 

		return 0; 
	};

	SectionAddressLimits section_address_limits = { 
		std::numeric_limits<std::uintptr_t>::max(),
		std::numeric_limits<std::uintptr_t>::max(), 
		std::numeric_limits<std::uintptr_t>::min(), 
		std::numeric_limits<std::uintptr_t>::min()
	};

	IterSec(pe.get(), L_getSectionAddressLimits, &section_address_limits); 

	switch(source_type) { 
		case AddressType::PhysicalOffset: 
		{ 
			if(address >= section_address_limits.highest_offset) { 
				return false; 
			}

			if(destination_type == AddressType::RelativeVirtualAddress) { 

				struct CallbackData final { 
					bool found; 
					std::uint64_t address; 
					std::uint64_t result;
				};

				auto L_inspectSection = [](void *N, 
							   const peparse::VA &secBase, 
							   const std::string &secName,
							   const peparse::image_section_header &s, 
							   const peparse::bounded_buffer *data) -> int 
				{
					static_cast<void>(secBase); 
					static_cast<void>(secName); 
					static_cast<void>(data); 


					std::uintptr_t sectionBaseOffset = s.PointerToRawData;
					std::uintptr_t sectionEndOffset = sectionBaseOffset; 

					if(s.SizeOfRawData != 0) { 
						sectionEndOffset += s.SizeOfRawData; 
					} else { 

						sectionEndOffset += s.Misc.VirtualSize; 
					}

					auto callback_data = static_cast<CallbackData *>(N);

					if(callback_data->address >= sectionBaseOffset &&
					   callback_data->address <  sectionEndOffset) { 

						callback_data->result = s.VirtualAddress + (callback_data->address - s.PointerToRawData); 
						callback_data->found = true; 

						return 1;

					}
					return 0; 
				};

				CallbackData callback_data  = {false, address, 0U}; 
				IterSec(pe.get(), L_inspectSection, &callback_data); 

				if(!callback_data.found) { 
					return false;
				}

				result = callback_data.result; 
				return true; 

			} else if(destination_type == AddressType::VirtualAddress) { 
				std::uint64_t rva = 0U; 
				if(!convertAddress(pe, 
						   address, 
						   source_type, 
						   AddressType::RelativeVirtualAddress,
						   rva)) { 
					return false; 
				}

				result = image_base_address + rva; 
				return true; 
			}
			return false; 
		}

		case AddressType::RelativeVirtualAddress: 
		{

			if (address < section_address_limits.lowest_rva) {
        result = address;
        return true;
      } else if (address >= section_address_limits.highest_rva) {
        return false;
      }

      if (destination_type == AddressType::PhysicalOffset) {
        struct CallbackData final {
          bool found;
          std::uint64_t address;
          std::uint64_t result;
        };

        auto L_inspectSection = [](void *N,
                                   const peparse::VA &secBase,
                                   const std::string &secName,
                                   const peparse::image_section_header &s,
                                   const peparse::bounded_buffer *data) -> int {
          static_cast<void>(secBase);
          static_cast<void>(secName);
          static_cast<void>(data);

          std::uintptr_t sectionBaseAddress = s.VirtualAddress;
          std::uintptr_t sectionEndAddress =
              sectionBaseAddress + s.Misc.VirtualSize;

          auto callback_data = static_cast<CallbackData *>(N);
          if (callback_data->address >= sectionBaseAddress &&
              callback_data->address < sectionEndAddress) {
            callback_data->result =
                s.PointerToRawData +
                (callback_data->address - sectionBaseAddress);

            callback_data->found = true;
            return 1;
          }

          return 0;
        };

        CallbackData callback_data = {false, address, 0U};
        IterSec(pe.get(), L_inspectSection, &callback_data);

        if (!callback_data.found) {
          return false;
        }

        result = callback_data.result;
        return true;

      } else if (destination_type == AddressType::VirtualAddress) {
        result = image_base_address + address;
        return true;
      }

      return false;
		}

		case AddressType::VirtualAddress: 
		{ 

			 if (address < image_base_address) {
        return false;
      }

      std::uint64_t rva = address - image_base_address;
      return convertAddress(pe,
                            rva,
                            AddressType::RelativeVirtualAddress,
                            destination_type,
                            result);
		}	

		default: {
			 return false; 
		}		
	}
}

int main(int argc, char** argv){
	csh handle; 
	cs_insn * insn; 
	size_t count; 

	if(cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) 
	{
		std::cerr << "Could not start capstone disassembler" << std::endl; 
		return -1; 
	}


    auto pe = open_exe("EXAMPLE_TEST.EXE"); 

    if(!pe) { 
        std::cerr << "Could not open file" << std::endl; 
        std::cerr << peparse::GetPEErr() << " (" << peparse::GetPEErrString() << ")\n"; 

        std::cerr << "Location: " << peparse::GetPEErrLoc() << std::endl; 

        return - 3; 
    }

    std::uint64_t image_base_address = 0U; 

    if(pe->peHeader.nt.FileHeader.Machine == peparse::IMAGE_FILE_MACHINE_AMD64) { 
        image_base_address = pe->peHeader.nt.OptionalHeader64.ImageBase; 
    } else { 
        image_base_address = pe->peHeader.nt.OptionalHeader.ImageBase; 
    }
    
    std::cout << "Image Base Address: 0x" << std::hex << image_base_address << std::endl;

	count = cs_disasm(handle, pe->fileBuffer->buf + image_base_address, pe->fileBuffer->bufLen, image_base_address, 0, &insn); 

	std::cout << "Disassembled:" << count << " instructions" << std::endl;

	if(count > 0) { 
		size_t j; 
		for(j = 0; j < count; j++) { 
			printf("0x%llX:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count); 
	} else
		std::cerr << "Failed to disassemble the given code!\n" << std::endl; 

	cs_close(&handle); 


	return 0;	
}
