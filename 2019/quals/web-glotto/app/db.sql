-- Copyright 2019 Google LLC
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http:--www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- phpMyAdmin SQL Dump
-- version 4.6.6deb5
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: Jun 12, 2019 at 05:22 AM
-- Server version: 5.7.21-1
-- PHP Version: 5.6.24-1+b3

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

-- --------------------------------------------------------

--
-- Table structure for table `april`
--

DROP TABLE IF EXISTS `april`;
CREATE TABLE `april` (
  `date` date NOT NULL,
  `winner` varchar(16) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `april`
--

INSERT INTO `april` (`date`, `winner`) VALUES
('2019-03-01', '4KYEC00RC5BZ'),
('2019-04-02', '7AET1KPGKUG4'),
('2019-04-06', 'UDT5LEWRSWM9'),
('2019-04-10', 'OQQRH90KDJH1'),
('2019-04-12', '2JTBMJW9HZOO'),
('2019-04-14', 'L4CY1JMRBEAW'),
('2019-04-18', '8DKYRPIO4QUW'),
('2019-04-22', 'BFWQCWYK9VHJ'),
('2019-04-27', '31OSKU57KV49');

-- --------------------------------------------------------

--
-- Table structure for table `june`
--

DROP TABLE IF EXISTS `june`;
CREATE TABLE `june` (
  `date` date NOT NULL,
  `winner` varchar(16) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `june`
--

INSERT INTO `june` (`date`, `winner`) VALUES
('2019-03-01', '1JJL716ATSCZ'),
('2019-06-04', 'YELDF36F4TW7'),
('2019-06-08', 'WXRJP8D4KKJQ'),
('2019-06-22', 'G0O9L3XPS3IR');

-- --------------------------------------------------------

--
-- Table structure for table `march`
--

DROP TABLE IF EXISTS `march`;
CREATE TABLE `march` (
  `date` date NOT NULL,
  `winner` varchar(16) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `march`
--

INSERT INTO `march` (`date`, `winner`) VALUES
('2019-03-01', 'CA5G8VIB6UC9'),
('2019-03-05', '01VJNN9RHJAC'),
('2019-03-10', '1WSNL48OLSAJ'),
('2019-03-13', 'UN683EI26G56'),
('2019-03-18', 'YYKCXJKAK3KV'),
('2019-03-23', '00HE2T21U15H'),
('2019-03-28', 'D5VBHEDB9YGF'),
('2019-03-30', 'I6I8UV5Q64L0');

-- --------------------------------------------------------

--
-- Table structure for table `may`
--

DROP TABLE IF EXISTS `may`;
CREATE TABLE `may` (
  `date` date NOT NULL,
  `winner` varchar(16) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Dumping data for table `may`
--

INSERT INTO `may` (`date`, `winner`) VALUES
('2019-03-01', 'O3QZ2P6JNSSA'),
('2019-05-04', 'PQ8ZW6TI1JH7'),
('2019-05-09', 'OWGVFW0XPLHE'),
('2019-05-10', 'OMZRJWA7WWBC'),
('2019-05-16', 'KRRNDWFFIB08'),
('2019-05-20', 'ZJR7ANXVBLEF'),
('2019-05-25', '8GAB09Z4Q88A');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `april`
--
ALTER TABLE `april`
  ADD PRIMARY KEY (`date`);

--
-- Indexes for table `june`
--
ALTER TABLE `june`
  ADD PRIMARY KEY (`date`);

--
-- Indexes for table `march`
--
ALTER TABLE `march`
  ADD PRIMARY KEY (`date`);

--
-- Indexes for table `may`
--
ALTER TABLE `may`
  ADD PRIMARY KEY (`date`);

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
