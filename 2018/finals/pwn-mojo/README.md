= Mojo Rising =

This is a sandbox breakout challenge using a Mojo bug to break out of the Chrome sandbox.

This means that the chrome sandbox needs to actually run in the container - I have been
using --cap-add=SYS_ADMIN in my docker command, seems to be necessary for me but maybe
someone who understands docker/linux capabilities better can resolve this.

Challenge should be run with a timeout > 15 seconds, since there is an inbuilt timer in
the challenge. If the timeout needs to be reduced, then the --timeout setting in service.py
should also be reduced to match.

Teams will need to setup a webserver with a valid ssl certificate in order to solve the 
challenge.
