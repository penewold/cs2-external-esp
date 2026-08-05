#pragma once
#ifndef _PPROCESS_HPP_
#define _PPROCESS_HPP_

#include <vector>
#include <math.h>
#include <string>
#include <iostream>

struct MemoryRegion
{
	uintptr_t start;
	uintptr_t end;
	size_t size;
};

struct ProcessModule
{
	uintptr_t base, size;
};

class pProcess
{
public:
	uint32_t      pid_; // process id
	ProcessModule base_client_;

public:
	bool AttachProcess(std::string process_name);
	void Close();

public:
	ProcessModule             GetModule(std::string module_name);
	//LPVOID		          Allocate(size_t size_in_bytes);  implement with pTrace + mmap later? or delete
	bool                      read_raw(uintptr_t address, void* buffer, size_t size);
	std::vector<MemoryRegion> GetMemoryRegions(ProcessModule module);
	bool                      IsValid();

	template<class T>
	void write(uintptr_t address, T value)
	{
		write_impl(address, &value, sizeof(T));
	}

	template<class T>
	T read(uintptr_t address)
	{
		T buffer{};

		this->read_impl(address, &buffer, sizeof(T));
		return buffer;
	}

	void write_bytes(uintptr_t address, const std::vector<uint8_t>& patch)
	{
		write_impl(address, patch.data(), sizeof(uint8_t) * patch.size());
	}

	uintptr_t read_multi_address(uintptr_t ptr, std::vector<uintptr_t> offsets)
	{
		uintptr_t buffer = ptr;
		for (int i = 0; i < offsets.size(); i++)
			buffer = this->read<uintptr_t>(buffer + offsets[i]);

		return buffer;
	}

	template <typename T>
	T read_multi(uintptr_t base, std::vector<uintptr_t> offsets)
	{
		uintptr_t buffer = base;
		for (int i = 0; i < offsets.size() - 1; i++)
		{
			buffer = this->read<uintptr_t>(buffer + offsets[i]);
		}
		return this->read<T>(buffer + offsets.back());
	}

	uintptr_t FindSignature(std::vector<uint8_t> signature)
	{
		std::unique_ptr<uint8_t[]> data;
		data = std::make_unique<uint8_t[]>(this->base_client_.size);

		if (!this->read_raw(this->base_client_.base, data.get(), this->base_client_.size)) {
			return NULL;
		}

		for (uintptr_t i = 0; i < this->base_client_.size; i++)
		{
			for (uintptr_t j = 0; j < signature.size(); j++)
			{
				if (signature.at(j) == 0x00)
					continue;

				if (*reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(&data[i + j])) == signature.at(j))
				{
					if (j == signature.size() - 1)
						return this->base_client_.base + i;
					continue;
				}
				break;
			}
		}
		return NULL;
	}

	uintptr_t FindSignature(ProcessModule target_module, std::vector<uint8_t> signature)
	{
		std::unique_ptr<uint8_t[]> data;
		data = std::make_unique<uint8_t[]>(0xFFFFFFF);

		if (!this->read_raw(target_module.base, data.get(), 0xFFFFFFF)) {
			return NULL;
		}

		for (uintptr_t i = 0; i < 0xFFFFFFF; i++)
		{
			for (uintptr_t j = 0; j < signature.size(); j++)
			{
				if (signature.at(j) == 0x00)
					continue;

				if (*reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(&data[i + j])) == signature.at(j))
				{
					if (j == signature.size() - 1)
						return this->base_client_.base + i;
					continue;
				}
				break;
			}
		}
		return NULL;
	}

	uintptr_t FindCodeCave(uint32_t length_in_bytes)
	{
		std::vector<uint8_t> cave_pattern = {};

		for (uint32_t i = 0; i < length_in_bytes; i++) {
			cave_pattern.push_back(0x00);
		}

		return FindSignature(cave_pattern);
	}

	template<class T>
	uintptr_t ReadOffsetFromSignature(std::vector<uint8_t> signature, uint8_t offset) // offset example: "FF 05 ->22628B01<-" offset is 2
	{
		uintptr_t pattern_address = this->FindSignature(signature);
		if (!pattern_address)
			return 0x0;

		T offset_value = this->read<T>(pattern_address + offset);
		return pattern_address + offset_value + offset + sizeof(T);
	}

private:
	uint32_t FindProcessIdByProcessName(const char* process_name);
	uint32_t FindProcessIdByWindowName(const char* window_name);
	//HWND GetWindowHandleFromProcessId(DWORD ProcessId);
	size_t read_impl(uintptr_t address, void* buffer, size_t size);
	size_t write_impl(uintptr_t address, const void* value, size_t size);
};
#endif