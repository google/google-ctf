# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
##########################################################################
##########################################################################
############################## Engraver ##################################
##########################################################################
##########################################################################
# 
# Script to program the LewanSoul LeArm robot for engraving letters with a 
# laser pointer. The primary purpose of this script is for Google CTF 2022. 
# 
# Note: This script assumes that a laser pointer is attached to robot grip 
# servo in a way that closing/opening the servo switches on/off the laser 
# pointer. This script imports the xArmServoController repository (MIT 
# License) in GitHub and needs slight changes to thresholds in the library 
# to allow the LeArm robot servos to rotate at their maximum range. 
# To be more specific, in controller.py in the the abovementioned repo, one
# need to change the if statment conditions that sets the range of 0-to-1000
# to 0-3000 to allow a full 180 degree rotation on the servos. 
# 
# Author: Vafa Andalibi
#

from time import sleep

import xarm


class Robot:
    """
    A class representing the robot arm for engraving letters.
    Currently, the letters with diagonal are missing: A, M, N, V, W, X, Z

    Attributes:
            defaultSpeed    Default speed of the servos moving
            debug           Show/hide debug information
            arm             LeArm arm object
            currentPosition Current position of each servo
            rightOffset     The amount the arm moves for a right or left move
            downOffset      The amount the arm moves for a down or up move
            mapping         The mapping between each character to a method of the class
    """

    def __init__(self, debug=False):
        self.defaultSpeed = 1500
        self.debug = debug
        self.arm = xarm.Controller('USB', debug=self.debug)
        self.currentPosition = {
            1: 1500,
            2: 1500,
            3: 1500,
            4: 1500,
            5: 1500,
            6: 1500
        }
        self.rightOffset = 200
        self.downOffset = 200
        self.leftMoveOffset = 0
        self.mapping = {
            "a": self.a,
            "b": self.b,
            "C": self.C,
            "d": self.d,
            "E": self.E,
            "e": self.e,
            "F": self.F,
            "G": self.G,
            "H": self.H,
            "I": self.I,
            "J": self.J,
            "L": self.L,
            "m": self.m,
            "n": self.n,
            "O": self.O,
            "P": self.P,
            "q": self.q,
            "r": self.r,
            "S": self.S,
            "T": self.T,
            "U": self.U,
            "y": self.y,
            "6": self.six,
            "3": self.three,
            "_": self.hyphen,
            "{": self.braceopen,
            "}": self.braceclose
        }

    def print_positions(self):
        """
        Prints the current position of servos
        
        :return: None
        """
        print(self.currentPosition)

    def reset(self):
        """
        Resets the servos position
        
        :return: None 
        """
        for i in range(6, 1, -1):
            self.set_position(i, 1500, self.defaultSpeed, wait=True)

    def set_position(self, *args, wait=False):
        """
        Set a servo position while recording the new position
        
        :param args: arguments passed to the robot API
        :param wait: waiting passed to the robot API
        :return: None
        """
        self.currentPosition[args[0]] = args[1]
        self.arm.setPosition(*args, wait)
        if self.debug:
            self.print_positions()

    def set_all_positions(self, servo_positions, *args, wait=False):
        """
        Set position of all servos 
        
        :param servo_positions: dictionary of servos new position 
        :param args: arguments passed to the robot API
        :param wait: waiting passed to the robot API
        :return: None
        """
        for servo, newPos in servo_positions:
            self.currentPosition[servo] = newPos
        self.arm.setPosition(servo_positions, *args, wait)

    def left(self):
        """
        Move arm to left
        
        :return: None
        """
        self.set_position(2, self.currentPosition[2] + self.rightOffset, 1000, wait=True)
        sleep(0.8)

    def right(self):
        """
        Move arm to right
        
        :return: None 
        """
        self.set_position(2, self.currentPosition[2] - self.rightOffset, 1000, wait=True)
        sleep(0.8)

    def half_left(self):
        """
        Move arm half-way left.
        
        :return: None
        """
        self.set_position(2, self.currentPosition[2] + self.rightOffset // 2, 1000, wait=True)
        sleep(0.4)

    def half_right(self):
        """
        Move arm half-way right.

        :return: None
        """
        self.set_position(2, self.currentPosition[2] - self.rightOffset // 2, 1000, wait=True)
        sleep(0.4)

    def down(self):
        """
        Move arm down.

        :return: None
        """
        self.set_position(3, self.currentPosition[3] - self.downOffset, 500, wait=True)
        sleep(0.8)

    def up(self):
        """
        Move arm up.

        :return: None
        """
        self.set_position(3, self.currentPosition[3] + self.downOffset, 500, wait=True)
        sleep(0.4)

    def half_down(self):
        """
        Move arm half-way down.

        :return: None
        """
        self.set_position(3, self.currentPosition[3] - self.downOffset // 2, 500, wait=True)
        sleep(0.4)

    def half_up(self):
        """
        Move arm half-way up.

        :return: None
        """
        self.set_position(3, self.currentPosition[3] + self.downOffset // 2, 500, wait=True)
        sleep(0.4)

    def laser_on(self):
        """
        Switch on the laser pointer.

        :return: None
        """
        self.set_position(1, 2400, 500)
        sleep(0.5)

    def laser_off(self):
        """
        Switch off the laser pointer.

        :return: None
        """
        self.set_position(1, 2300, 500)
        sleep(0.5)

    def writing_position(self):
        """
        Get into writing position with laser pointer off.

        :return: None
        """
        self.laser_off()
        self.set_position(2, 1300, self.defaultSpeed)
        self.set_position(3, 1700, self.defaultSpeed)
        self.set_position(4, 2500, self.defaultSpeed)
        self.set_position(5, 1600, self.defaultSpeed)
        self.set_position(6, 1500 + self.leftMoveOffset, self.defaultSpeed)
        sleep(1.5)

    def top_left(self):
        """
        Get into the top left position with laser pointer off.

        :return: None
        """
        self.writing_position()
        self.left()

    def top_right(self):
        """
        Get into the top right position with laser pointer off.

        :return: None
        """
        self.writing_position()

    def bottom_left(self):
        """
        Get into the bottom left position with laser pointer off.

        :return: None
        """
        self.writing_position()
        self.left()
        self.down()

    def bottom_right(self):
        """
        Get into the bottom right position with laser pointer off.

        :return: None
        """
        self.writing_position()
        self.down()

    def mid_top(self):
        """
        Get into the middle top position with laser pointer off.

        :return: None
        """
        self.writing_position()
        self.half_left()

    def mid_down(self):
        """
        Get into the middle down position with laser pointer off.

        :return: None
        """
        self.writing_position()
        self.down()
        self.half_left()

    def mid_left(self):
        """
        Get into the middle left position with laser pointer off.

        :return: None
        """
        self.writing_position()
        self.left()
        self.half_down()

    def mid_right(self):
        """
        Get into the middle right position with laser pointer off.

        :return: None
        """
        self.writing_position()
        self.half_down()

    def a(self):
        """
        Engrave lower letter 'a'.

        :return: None
        """
        # Get into writing position
        self.top_left() 
        # Engrave
        self.laser_on(), self.right(), self.down(), self.left(), self.half_up(), self.right()
        # Get into default position
        self.top_right()

    def b(self):
        """
        Engrave lower letter 'b'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.down(), self.laser_off(), self.mid_left(), self.laser_on(), self.half_right(), self.half_down(), self.half_left()
        # Get into default position
        self.top_right()

    def C(self):
        """
        Engrave upper letter 'C'.

        :return: None
        """
        # Engrave
        self.laser_on(), self.left(), self.down(), self.right() 
        # Get into default position
        self.top_right()

    def d(self):
        """
        Engrave lower letter 'd'.

        :return: None
        """
        # Engrave
        self.laser_on(), self.down(), self.half_up(), self.half_left(), self.half_down(), self.half_right()
        # Get into default position
        self.top_right()

    def E(self):
        """
        Engrave upper letter 'E'.

        :return: None
        """
        # Engrave
        self.laser_on(), self.left(), self.down(), self.right(), self.mid_left(), self.laser_on(), self.right()
        # Get into default position
        self.top_right()

    def e(self):
        """
        Engrave lower letter 'e'.

        :return: None
        """
        # Get into writing position
        self.mid_left()
        # Engrave
        self.laser_on(), self.right(), self.half_up(), self.left(), self.down(), self.right()
        # Get into default position
        self.top_right()

    def F(self):
        """
        Engrave upper letter 'F'.

        :return: None
        """
        # Engrave
        self.laser_on(), self.left(), self.down(), self.laser_off(), self.half_up(), self.laser_on(), self.right()
        # Get into default position
        self.top_right()

    def G(self):
        """
        Engrave upper letter 'G'.

        :return: None
        """
        # Engrave
        self.laser_on(), self.left(), self.down(), self.right(), self.half_up(), self.half_left()
        # Get into default position
        self.top_right()

    def H(self):
        """
        Engrave upper letter 'H'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.down(), self.top_right(), self.laser_on(), self.down(), self.mid_left(), self.laser_on(), self.right()
        # Get into default position
        self.top_right()

    def I(self):
        """
        Engrave upper letter 'I'.

        :return: None
        """
        # Get into writing position
        self.mid_top()
        # Engrave
        self.laser_on(), self.down(), self.top_left(), self.laser_on(), self.right(), self.bottom_left(), self.laser_on(), self.right()
        # Get into default position
        self.top_right()

    def J(self):
        """
        Engrave upper letter 'J'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.right(), self.mid_top(), self.laser_on(), self.down(), self.half_left(), self.half_up()
        # Get into default position
        self.top_right()

    def L(self):
        """
        Engrave upper letter 'L'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.down(), self.right()
        # Get into default position
        self.top_right()

    def m(self):
        """
        Engrave lower letter 'm'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.down(), self.up(), self.half_right(), self.down(), self.up(), self.half_right(), self.down()
        # Get into default position
        self.top_right()

    def n(self):
        """
        Engrave lower letter 'n'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.down(), self.up(), self.half_right(), self.down()
        # Get into default position
        self.top_right()

    def O(self):
        """
        Engrave upper letter 'O'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.right(), self.down(), self.left(), self.up()
        # Get into default position
        self.top_right()

    def P(self):
        """
        Engrave upper letter 'P'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.down(), self.top_left(), self.laser_on(), self.half_right(), self.half_down(), self.half_left()
        # Get into default position
        self.top_right()

    def q(self):
        """
        Engrave lower letter 'q'.

        :return: None
        """
        # Get into writing position
        self.laser_on()
        # Engrave
        self.left(), self.half_down(), self.right(), self.top_right(), self.laser_on(), self.down()
        # Get into default position
        self.top_right()

    def r(self):
        """
        Engrave lower letter 'r'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.down(), self.up(), self.right()
        # Get into default position
        self.top_right()

    def S(self):
        """
        Engrave upper letter 'S'.

        :return: None
        """
        # Engrave
        self.laser_on(), self.left(), self.half_down(), self.right(), self.half_down(), self.left()
        # Get into default position
        self.top_right()

    def T(self):
        """
        Engrave upper letter 'T'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.right(), self.mid_top(), self.laser_on(), self.down()
        # Get into default position
        self.top_right()

    def U(self):
        """
        Engrave upper letter 'U'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.down(), self.right(), self.up()
        # Get into default position
        self.top_right()

    def y(self):
        """
        Engrave lower letter 'y'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.half_down(), self.right(), self.half_up(), self.down(), self.left()
        # Get into default position
        self.top_right()

    def three(self):
        """
        Engrave the number three '3'.

        :return: None
        """
        # Get into writing position
        self.top_left()
        # Engrave
        self.laser_on(), self.right(), self.half_down(), self.left(), self.right(), self.half_down(), self.left()
        # Get into default position
        self.top_right()

    def six(self):
        """
        Engrave the number six '6'.

        :return: None
        """
        # Engrave
        self.laser_on(), self.left(), self.down(), self.right(), self.half_up(), self.left()
        # Get into default position
        self.top_right()

    def hyphen(self):
        """
        Engrave the symbol hyphen '_'.

        :return: None
        """
        # Get into writing position
        self.bottom_left()
        # Engrave
        self.laser_on(), self.right()
        # Get into default position
        self.top_right()

    def braceopen(self):
        """
        Engrave the symbol brace open '{'.

        :return: None
        """
        # Get into writing position
        self.mid_top()
        # Engrave
        self.laser_on(), self.half_left(), self.half_down()
        self.set_position(2, self.currentPosition[2] + 50, 400, wait=True)
        self.set_position(2, self.currentPosition[2] - 50, 400, wait=True)
        self.half_down(), self.half_right()
        # Get into default position
        self.top_right()

    def braceclose(self):
        """
        Engrave the symbol brace close '}'.

        :return: None
        """
        # Get into writing position
        self.mid_top()
        # Engrave
        self.laser_on(), self.half_right(), self.half_down()
        self.set_position(2, self.currentPosition[2] - 50, 400, wait=True)
        self.set_position(2, self.currentPosition[2] + 50, 400, wait=True)
        self.half_down(), self.half_left()
        # Get into default position
        self.top_right()

    def moveright(self):
        """
        Move the base right for writing letters one after another instead of overwriting.

        :return: None
        """
        self.set_position(6, self.currentPosition[6] - 100, 400, wait=True)
        sleep(0.8)

    def type(self, phrase):
        """
        Engrave a phrase.

        :return: None
        """
        for letter in phrase:
            self.mapping[letter]()


if __name__ == "__main__":
    r = Robot(debug=True)
    r.writing_position()
    flag = "CTF{6_d3GrEe_OF_Fr3edOm}"
    r.type(flag)
