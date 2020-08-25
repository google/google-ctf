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
#undef F_CPU
#define F_CPU 1000000UL

#include <avr/io.h>
#include <avr/sleep.h>
#include <avr/interrupt.h>
#include <util/delay.h>
#include <avr/cpufunc.h>
#include <stdio.h>
#include <string.h>

#define BAUD 125000UL
#include <util/setbaud.h>

#ifndef PASS1
#define PASS1 "PASSWORD_REDACTED_XYZ"
#endif

#ifndef PASS2
#define PASS2 "TOPSECRET_PASSWORD_ALSO_REDACTED_TOPSECRET"
#endif

#ifndef FLAG
#define FLAG "CTF{_REAL_FLAG_IS_ON_THE_SERVER_}"
#endif

const char* correctpass = PASS1;
const char* top_secret_password = PASS2;
const char* top_secret_data = 
	"INTELLIGENCE REPORT:\n"
	"FLAG CAPTURED FROM ENEMY.\n"
	"FLAG IS " FLAG ".";

char buf[512];
char secret[256] = 
	"Operation SIERRA TANGO ROMEO:\n"
	"Radio frequency: 13.37MHz\n"
	"Received message: ATTACK AT DAWN\n";
char timer_status[16] = "off";

volatile char logged_in;
int top_secret_index;

volatile char uart_ready;
ISR(USART_RX_vect) {
	uart_ready = 1;
}

void uart_init(void) {
    UBRR0H = UBRRH_VALUE;
    UBRR0L = UBRRL_VALUE;

    UCSR0C = (1<<UCSZ01) | (1<<UCSZ00);
    UCSR0B = (1<<RXEN0) | (1<<TXEN0) | (1<<RXCIE0);
}

static int uart_getchar(FILE* stream) {
	while (1) {
		cli();
		if (!uart_ready) {
			sleep_enable();
			sei();
			sleep_cpu();
			sleep_disable();
		}
		cli();
		if (uart_ready) {
			uart_ready = 0;
			unsigned int c = UDR0;
			sei();
			return c;
		}
		sei();
	}
}

static int uart_putchar(char c, FILE* stream) {
	loop_until_bit_is_set(UCSR0A, UDRE0);
	UDR0 = c;
	return 0;
}
static FILE uart = FDEV_SETUP_STREAM(uart_putchar, uart_getchar, _FDEV_SETUP_RW);

void quit() {
	printf("Quitting...\n");
	_delay_ms(100);
	cli();
	sleep_enable();
	sleep_cpu();
	while (1);
}

volatile uint32_t overflow_count;
uint32_t get_time() {
	uint32_t t;
	cli();
	t = (overflow_count << 16) + TCNT1;
	sei();
	return t;
}

void timer_on_off(char enable) {
	overflow_count = 0;
	strcpy(timer_status, enable ? "on" : "off");
	if (enable) {
		TCCR1B = (1<<CS10);
		sei();
	}
	else {
		TCCR1B = 0;
	}
}

ISR(TIMER1_OVF_vect) {
	if (!logged_in) {
		overflow_count++;
		// Allow ten seconds.
		if (overflow_count >= ((10*F_CPU)>>16)) {
			printf("Timed out logging in.\n");
			quit();
		}
	}
	else {
		// If logged in, timer is used to securely copy top secret data.
		secret[top_secret_index] = top_secret_data[top_secret_index];
		timer_on_off(top_secret_data[top_secret_index]);
		top_secret_index++;
	}
}

void read_data(char* buf) {
	scanf("%200s", buf);
}

void print_timer_status() {
	printf("Timer: %s.\n", timer_status);
}

int main() {
	uart_init();
	stdout = &uart;
	stdin = &uart;

	TCCR1A = 0;
	TIMSK1 = (1<<TOIE1);

	printf("Initialized.\n");
	printf("Welcome to secret military database. Press ENTER to continue.\n");
	char enter = uart_getchar(0);
	if (enter != '\n') {
		quit();
	}

	timer_on_off(1);

	while (1) {
		print_timer_status();
		printf("Uptime: %ldus\n", get_time());
		printf("Login: ");
		read_data(buf);
		printf("Password: ");
		read_data(buf+256);
		if (strcmp(buf, "agent") == 0 && strcmp(buf+256, correctpass) == 0) {
			printf("Access granted.\n");
			break;
		}
		printf("Wrong user/password.\n");
	}

	cli();
	timer_on_off(0);
	sei();

	logged_in = 1;

	while (1) {
		print_timer_status();
		printf("Menu:\n");
		printf("1. Store secret data.\n");
		printf("2. Read secret data.\n");
		printf("3. Copy top secret data.\n");
		printf("4. Exit.\n");
		printf("Choice: ");
		read_data(buf);
		switch (buf[0]) {
			case '1':
			{
				printf("Secret: ");
				read_data(secret);
				break;
			}
			case '2':
			{
				printf("Stored secret:\n---\n%s\n---\n", secret);
				break;
			}
			case '3':
			{
				printf("Enter top secret data access code: ");
				read_data(buf);
				char pw_bad = 0;
				for (int i = 0; top_secret_password[i]; i++) {
					pw_bad |= top_secret_password[i]^buf[i];
				}
				if (pw_bad) {
					printf("Access denied.\n");
					break;
				}
				printf("Access granted.\nCopying top secret data...\n");
				timer_on_off(1);
				while (TCCR1B);
				printf("Done.\n");
				break;
			}
			case '4':
			{
				quit();
				break;
			}
			default:
			{
				printf("Invalid option.\n");
				break;
			}
		}
	}
	quit();
}

