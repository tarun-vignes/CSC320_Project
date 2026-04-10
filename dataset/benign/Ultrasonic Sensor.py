'''
Program: Create a Motion Detector
Programmers: Michael Beehler and Joseph DiMartino
Date: 2/7
'''
'''
Speed of sound = 34300 cm/s
Duration: time to leave (trig) then return (echo)
Distance = SoS * Duration
'''
import RPi.GPIO as GPIO
from time import sleep
import time

LED_far = 6
LED_close = 5
TrigPin = 18
EchoPin = 27
TRIGGER_TIME = .1
speed_of_sound = 34300

GPIO.setmode(GPIO.BCM)
GPIO.setup(LED_far, GPIO.OUT)
GPIO.setup(LED_close, GPIO.OUT)
GPIO.setup(TrigPin, GPIO.OUT)
GPIO.setup(EchoPin, GPIO.IN)

while True:
    GPIO.output(TrigPin, GPIO.HIGH)
    sleep(TRIGGER_TIME)
    GPIO.output(TrigPin, GPIO.LOW)
    
    while (GPIO.input(EchoPin) == GPIO.LOW):
        start = time.time()
        
    while (GPIO.input(EchoPin) == GPIO.HIGH):
        end = time.time()
        
    duration = end - start
    distance = (speed_of_sound * duration) / 2


    if distance <= 5:
        GPIO.output(LED_close, GPIO.HIGH)
        GPIO.output(LED_far, GPIO.HIGH)
    elif distance <= 10:
        GPIO.output(LED_far, GPIO.HIGH)
        GPIO.output(LED_close, GPIO.LOW)   
    else:
        GPIO.output(LED_far, GPIO.LOW)
        GPIO.output(LED_close, GPIO.LOW)
    sleep (2)
