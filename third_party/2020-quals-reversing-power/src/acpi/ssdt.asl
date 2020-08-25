// Copyright 2020 Google LLC
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

DefinitionBlock (
		"ssdt.aml",
		"SSDT",
		2,
		"", "", 0)
{
	Device(CHCK)
	{
		Name(_HID, "CHCK0001")
		Name(_CID, Package() {
			   "CHCK0001",
			   "CHCK",    
		})
		
		OperationRegion(KBDD, SystemIO, 0x60, 0x01)
		OperationRegion(KBDC, SystemIO, 0x64, 0x01)
		Field(KBDD, ByteAcc, NoLock, Preserve)
		{
			DTAR, 8,	// DaTA Register
		}
		Field(KBDC, ByteAcc, NoLock, Preserve)
		{
			CSTR, 8,	// Command and STatus Register
		}

		Name(KBDA, Buffer() {
			0x2A, 0x2E, 0xAE, 0x14, 0x94, 0x21, 0xA1, 0x1A, 0x9A, 0xAA, // CTF{
			0x1E, 0x9E, 0x2E, 0xAE, 0x19, 0x99, 0x17, 0x97, 0x2A, 0x0C, 0x8C, 0xAA, // acpi_
			0x32, 0xB2, 0x1E, 0x9E, 0x2E, 0xAE, 0x23, 0xA3, 0x17, 0x97, 0x31, 0xB1, 0x12, 0x92, 0x2A, 0x0C, 0x8C, 0xAA, // machine_
			0x26, 0xA6, 0x1E, 0x9E, 0x31, 0xB1, 0x22, 0xA2, 0x16, 0x96, 0x1E, 0x9E, 0x22, 0xA2, 0x12, 0x92, // language
			0x2A, 0x1B, 0x9B, 0xAA, 0x1C, 0x9C // }\n
		})
		Name(KBDB, Buffer(62) {})
		
		Method(WCMD, 0)		// Wait Command Ready
		{
			local0 = 1
			while ((local0 == 1))
			{
				local0 = CSTR
				local0 >>= 1
				local0 &= 1
			}
		}

		Method(WDTA, 0)
		{
			local0 = 0
			while ((local0 == 0))
			{
				local0 = CSTR
				local0 &= 1
			}
		}

		Method(CLRD, 0)
		{
			local0 = CSTR
			local0 &= 1

			while ((local0 == 1))
			{
				local1 = DTAR
				local0 = CSTR
				local0 &= 1
			}
		}

		Method(DINT, 0)
		{
			local0 = 0x44	// Translation enabled, POST, Port 1 interrupts disabled, Port 2 interrupts disabled
			WCMD ()
			CSTR = 0x60	// Set status byte
			WCMD ()
			DTAR = local0
		}

		Method(EINT, 0)
		{
			local0 = 0x47	// Translation enabled, POST, Port 1 interrupts enabled, Port 2 interrupts enabled
			WCMD ()
			CSTR = 0x60	// Set status byte
			WCMD ()
			DTAR = local0
		}
		
		Method(CHCK, 0)
		{
			DINT ()
			CLRD ()
			WDTA ()
			local0 = DTAR

			if ((local0 == 0x9C))	// Skip over enter release, if necessary
			{
				WDTA ()
				local0 = DTAR
			}
			local1 = 0

			// Normalise to left shift
			if ((local0 == 0x36))
			{
				local0 = 0x2A
			}

			KBDB[local1] = local0
			local1 += 1

			while ((local0 != 0x9C))
			{
				WDTA ()
				local0 = DTAR

				// Normalise to left shift
				if ((local0 == 0x36))
				{
					local0 = 0x2A
				}

				if ((local0 == 0xB6))
				{
					local0 = 0xAA
				}

				if ((local1 < 62))
				{
					KBDB[local1] = local0
					local1 += 1
				}
			}

			EINT ()

			if ((KBDA == KBDB))
			{
				Return (1)
			}
			Return (0)
		}
	}
}
