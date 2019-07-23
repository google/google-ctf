-- Copyright 2019 Google LLC
--
--Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--    https://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
-- drop then create table --
DROP TABLE IF EXISTS `blindtable`;
CREATE TABLE `blindtable` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT,
  `city` TEXT,
  `information1` TEXT
);


-- Dumping data for table `blindtable`
INSERT INTO `blindtable` VALUES 
(1,'paris','Welcome! Our center is located in 8 rue de Londres, 75008 Paris, Opening hours for this center is 10:00-19:00'),(2,'zurich','Welcome! Our center is located in Brandschenkestrasse 110, 8002 Zurich, Opening hours for this center is 8:00-17:00'),(3,'bangalore','Welcome! Our center is located in Tower E, 4th Floor, RMZ Infinity, No. 3, Swamy Vivekananda Rd, Bengaluru, Karnataka, Opening hours for this center is 10:00-20:00');

