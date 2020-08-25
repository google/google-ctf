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
#include <iostream>

template <typename RetType, typename InType>
RetType cast(InType in) {
  auto ret = dynamic_cast<RetType>(in);
  if (!ret) {
    std::cerr << "Unable to cast from object of type " << typeid(*in).name()
              << " to object of type " << typeid(ret).name() << std::endl;
  }
  assert(ret);
  return ret;
}