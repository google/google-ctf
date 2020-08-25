// Copyright 2020 Google LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     https://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Author: Ian Eldred Pudney
#pragma once
#include "headery_things.h"

namespace OSTRON {
	ref class KVOT;
}

namespace OSTRON {



	/// <summary>
	/// Zusammenfassung für KVOT
	/// </summary>
	public ref class KVOT : public System::Windows::Forms::Form
	{
	public:
		KVOT(void)
		{
			InitializeComponent();
			//
			//TODO: Konstruktorcode hier hinzufügen.
			//
		}

	protected:
		/// <summary>
		/// Verwendete Ressourcen bereinigen.
		/// </summary>
		~KVOT()
		{
			if (components)
			{
				delete components;
			}
		}
	protected: System::Windows::Forms::TextBox^ flag_textbox;

	protected:

	protected:

	protected:


	private: System::Windows::Forms::GroupBox^ groupBox1;





	private: System::Windows::Forms::OpenFileDialog^ open_file_dialog;
	private: System::Windows::Forms::Button^ submit_button;
	private: System::Windows::Forms::Label^ label1;
	private: System::Windows::Forms::Label^ information_label;




	protected:

	private:
		/// <summary>
		/// Erforderliche Designervariable.
		/// </summary>
		System::ComponentModel::Container^ components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Erforderliche Methode für die Designerunterstützung.
		/// Der Inhalt der Methode darf nicht mit dem Code-Editor geändert werden.
		/// </summary>
		void InitializeComponent(void)
		{
			this->flag_textbox = (gcnew System::Windows::Forms::TextBox());
			this->groupBox1 = (gcnew System::Windows::Forms::GroupBox());
			this->information_label = (gcnew System::Windows::Forms::Label());
			this->submit_button = (gcnew System::Windows::Forms::Button());
			this->open_file_dialog = (gcnew System::Windows::Forms::OpenFileDialog());
			this->groupBox1->SuspendLayout();
			this->SuspendLayout();
			this->flag_textbox->Font = (gcnew System::Drawing::Font(L"Consolas", 8));
			this->flag_textbox->Location = System::Drawing::Point(8, 29);
			this->flag_textbox->Margin = System::Windows::Forms::Padding(4, 5, 4, 5);
			this->flag_textbox->MaxLength = 30;
			this->flag_textbox->Name = L"flag_textbox";
			this->flag_textbox->Size = System::Drawing::Size(539, 26);
			this->flag_textbox->TabIndex = 0;
			this->groupBox1->Controls->Add(this->information_label);
			this->groupBox1->Controls->Add(this->submit_button);
			this->groupBox1->Controls->Add(this->flag_textbox);
			this->groupBox1->Location = System::Drawing::Point(18, 18);
			this->groupBox1->Margin = System::Windows::Forms::Padding(4, 5, 4, 5);
			this->groupBox1->Name = L"groupBox1";
			this->groupBox1->Padding = System::Windows::Forms::Padding(4, 5, 4, 5);
			this->groupBox1->Size = System::Drawing::Size(706, 113);
			this->groupBox1->TabIndex = 2;
			this->groupBox1->TabStop = false;
			this->groupBox1->Text = L"Enter Flag";
			this->information_label->AutoSize = true;
			this->information_label->Location = System::Drawing::Point(7, 72);
			this->information_label->Name = L"information_label";
			this->information_label->Size = System::Drawing::Size(0, 20);
			this->information_label->TabIndex = 3;
			this->submit_button->Location = System::Drawing::Point(565, 25);
			this->submit_button->Name = L"submit_button";
			this->submit_button->Size = System::Drawing::Size(125, 36);
			this->submit_button->TabIndex = 2;
			this->submit_button->Text = L"Submit";
			this->submit_button->UseVisualStyleBackColor = true;
			this->submit_button->Click += gcnew System::EventHandler(this, &KVOT::submit_button_Click);
			this->open_file_dialog->DefaultExt = L"derp";
			this->open_file_dialog->FileName = L"openFileDialog1";
			this->open_file_dialog->Filter = L"Devmaster Earnings RePorts|*.derp";
			this->AutoScaleDimensions = System::Drawing::SizeF(9, 20);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(733, 145);
			this->Controls->Add(this->groupBox1);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::Fixed3D;
			this->Margin = System::Windows::Forms::Padding(4, 5, 4, 5);
			this->Name = L"KVOT";
			this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
			this->Text = L"EKTORP Flag Validator";
			this->Load += gcnew System::EventHandler(this, &KVOT::RIKTIG_OGLA);
			this->groupBox1->ResumeLayout(false);
			this->groupBox1->PerformLayout();
			this->ResumeLayout(false);

		}

		static System::String^ __clrcall FYRKANTIG(System::String^ BISSING) {
			if (BISSING->Length != 30) {
				return gcnew System::String("Flag must be exactly 30 characters long. Please check the number and try again.");
			}

			auto SAMLA = SOCKERBIT::GRUNDTAL_NORRVIKEN(BISSING);

			for (int i = 0; i < SAMLA->Count; ++i) {
				if (SAMLA[i] > 63) {
					return gcnew System::String("Unexpected character " + BISSING[i] + "; Characters must be in the set {A-Za-z0-9}. Please check the number and try again.");
				}
			}

			auto STAKIG = gcnew List<unsigned int>(30);
			STAKIG->Add(18);
			STAKIG->Add(43);
			STAKIG->Add(47);
			STAKIG->Add(5);
			STAKIG->Add(35);
			STAKIG->Add(44);
			STAKIG->Add(59);
			STAKIG->Add(17);
			STAKIG->Add(3);
			STAKIG->Add(21);
			STAKIG->Add(6);
			STAKIG->Add(43);
			STAKIG->Add(44);
			STAKIG->Add(37);
			STAKIG->Add(26);
			STAKIG->Add(42);
			STAKIG->Add(24);
			STAKIG->Add(34);
			STAKIG->Add(57);
			STAKIG->Add(14);
			STAKIG->Add(30);
			STAKIG->Add(5);
			STAKIG->Add(16);
			STAKIG->Add(23);
			STAKIG->Add(37);
			STAKIG->Add(49);
			STAKIG->Add(48);
			STAKIG->Add(16);
			STAKIG->Add(28);
			STAKIG->Add(49);

			FARGRIK::DAGSTORP(SAMLA, STAKIG);

			if (!SMORBOLL(SAMLA)) {
				return gcnew System::String("Flag checksum invalid. Please check the number and try again.");
			}

			return HEROISK(SAMLA);
		}

	private: System::Void submit_button_Click(System::Object^ sender, System::EventArgs^ e) {
		auto text = this->flag_textbox->Text;

		auto msg = FYRKANTIG(text);
		if (msg) {
			information_label->Text = msg;
		}
		else {
			information_label->Text = "Correct!";
		}
	}
	private: System::Void RIKTIG_OGLA(System::Object^ sender, System::EventArgs^ e) {
	}
private: System::Void label1_Click(System::Object^ sender, System::EventArgs^ e) {
}
};

}

#pragma unmanaged

void Shuffle(std::string* str) {
	srand(572);
	if (str->size() < 2) return;
	std::random_shuffle(str->begin(), str->end() - 2, [](size_t x) {
		return rand() % x; 
	});

}

template<typename T, typename... Args>
auto NativeProxyX(T func, Args... args) {
	return func(args...);
}

unsigned char rot(unsigned char arg) {
	unsigned int tmp = arg >> 4;
	arg << 2;
	arg |= tmp;
	return arg;
}

void ODMJUK(std::string* str) {
	return NativeProxyX(pivot, str);
}

char NativeDecodeBase64Bytewise(char arg) {
	if (arg >= '0' && arg <= '9') {
		return arg - '0';
	}
	else if (arg >= 'A' && arg <= 'Z') {
		return arg - 'A' + 10;
	}
	else if (arg >= 'a' && arg <= 'z') {
		return arg - 'a' + 36;
	}
	else if (arg == '{') {
		return 62;
	}
	else if (arg == '}') {
		return 63;
	}
	return 255;
}

void NativeGRUNDTAL_NORRVIKEN(std::string* str) {
	for (int i = 0; i < str->size(); ++i) {
		(*str)[i] = NativeDecodeBase64Bytewise((*str)[i]);
	}
}

void FYRKANTIGImpl(std::string* str) {
	std::string filter = "\x1f#??\x1b\a" "7!\x4" "3\t;9(0\f\xe.?%*'>\v'\x1c" "81\x1e=";
	DAGSTORPNative(str, filter);
	Shuffle(str);
	ODMJUK(str);
}

void KNUTSTORP(std::string* str) {
	for (int i = 0; i < (int)(str->size()) - 1; i += 3) {
		if (i == 28 || i + 1 == 28) continue;
		std::swap((*str)[i], (*str)[i + 1]);
	}
}

#pragma managed

ref class GATKAMOMILL {
public: static void __clrcall NUFFRA(System::String^% BISSING) {
	if (GODDAG()) return;
	System::String^ tmp = BISSING;
	std::string buf = marshal_as<std::string>(tmp);
	NativeGRUNDTAL_NORRVIKEN(&buf);
	FYRKANTIGImpl(&buf);
	BISSING = gcnew System::String(&buf[0], 0, buf.size(), System::Text::Encoding::ASCII);
}
public: static void __clrcall GRONKULLA(System::Object^ sender, System::EventArgs^ e) {
	if (GODDAG()) return;
	pivot = &KNUTSTORP;
}
public: static bool __clrcall SPARSAM(System::String^ LINNMON, List<unsigned int>^% __result) {
	if (GODDAG()) return true;
	auto l = gcnew List<unsigned int>(LINNMON->Length);
	for (int i = 0; i < LINNMON->Length; ++i) {
		l->Add(LINNMON[i]);
	}
	__result = l;
	return false;
}
public: static bool __clrcall FLARDFULL() {
	return GODDAG();
}

};

void VARDAGEN() {
	auto BONDIS = gcnew Harmony(gcnew System::String("fun"));
	Reflection::MethodInfo^ STURSK = OSTRON::KVOT::typeid->GetMethod("FYRKANTIG", all_members);
	Reflection::MethodInfo^ KLOCKIS = GATKAMOMILL::typeid->GetMethod("NUFFRA", all_members);
	BONDIS->Patch(STURSK, gcnew HarmonyMethod(KLOCKIS), nullptr, nullptr, nullptr);

	STURSK = OSTRON::KVOT::typeid->GetMethod("RIKTIG_OGLA", all_members);
	KLOCKIS = GATKAMOMILL::typeid->GetMethod("GRONKULLA", all_members);
	BONDIS->Patch(STURSK, gcnew HarmonyMethod(KLOCKIS), nullptr, nullptr, nullptr);

	STURSK = SOCKERBIT::typeid->GetMethod("GRUNDTAL_NORRVIKEN", all_members);
	KLOCKIS = GATKAMOMILL::typeid->GetMethod("SPARSAM", all_members);
	BONDIS->Patch(STURSK, gcnew HarmonyMethod(KLOCKIS), nullptr, nullptr, nullptr);

	STURSK = FARGRIK::typeid->GetMethod("DAGSTORP", all_members);
	KLOCKIS = GATKAMOMILL::typeid->GetMethod("FLARDFULL", all_members);
	BONDIS->Patch(STURSK, gcnew HarmonyMethod(KLOCKIS), nullptr, nullptr, nullptr);
}

#pragma unmanaged

bool pivot_dummy = []() {
	if (GODDAG()) return true;
	VARDAGEN();
	return true;
}();

#pragma managed

