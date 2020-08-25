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
#include "stdafx.h"
#include "Form4.h"
#include <Windows.h>
#include <functional>
#include <memory>
#include <iostream>

using namespace System;
using namespace System::Windows::Forms;

void LaunchGui() {
	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false);
	Application::Run(gcnew OSTRON::KVOT());
}

void OpenConsole() {
	AllocConsole();
	AttachConsole(ATTACH_PARENT_PROCESS);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);
}

[STAThread]
int main(array<String^>^ args) {
	//OpenConsole();
	LaunchGui();
	return 0;
}