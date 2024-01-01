#!/bin/bash

openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem -subj "/C=US/ST=CA/O=Rocket/CN=localhost"