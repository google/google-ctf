/**
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Post from './classes/Post.ts';
import Log from './classes/Log.ts';
import Soda from './classes/Soda.ts';
import Vio from './classes/Vio.ts';
import Warning from './classes/Warning.ts';

const opts = {Post, Log, Vio, Soda, Warning};

export default {
    opts
};