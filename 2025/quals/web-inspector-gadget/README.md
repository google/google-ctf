# Inspector Gadget

Category: Web

Purpose: write custom gadget chain to get RCE in server running CoreNLP v4.5.8 with some custom modifications.

## Running The Challenge

1. Build Docker: `docker build -t web-inspector-gadget .`
2. Run Challenge: `docker run -it --network="host" web-inspector-gadget:latest`
   - Server is running on port 9000

## Troubleshooting

When an unexpected error occurs, a restart of the server solves the issue.

## Help Needed

See Dockerfile for commented-out setup with user that is not able to read flag directly, 
rather only through a binary named `read_flag`. 
I was not able to write an exploit that is able to run the binary and pass the output back via the network. 
Which is why it's commented out.
