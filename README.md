# mTCP TCP/IP library and applications for DOS

Home page: http://www.brutman.com/mTCP/mTCP.html

## Welcome mTCP!

This mTCP project is a TCP/IP library and applications for older IBM compatible personal computers
running DOS.  The applications include a DHCP client, FTP client and server, HTTP server, an IRC
client, NetCat (TCP only), mTCP NetDrive (network attached storage for DOS), Ping, and SNTP client,
and a Telnet client.  See the home page for details.

This is the official github repository for the project. While I prefer to distribute the source code
as a ZIP file on the home page I also recognize that people are using github for their projects and
they want a github repository to reference or fork from so that they can keep up with changes.

For detailed information on how the source code is structured please see the developers.pdf file. Topics include the directory
structure, what compiler to use, architecture and design notes, and miscellaneous notes for programming under DOS.

## Compiling and building

mTCP is compiled using Open Watcom 1.9 under Windows, cross compiled for 16 bit DOS. If you want to use Linux for your build
environment you will run into some problems with the case of the filenames; Windows is not case sensitive but Linux is. That
will be fixed in a future release.

Each program has its own directory and MAKEFILE. To compile a program, find its directory under APPS and run "wmake."

Each MAKEFILE also as a "patch" target, which runs a simple patch program against the EXE file.  The patch program
removes the ability to grow the near heap when far data pointers are used, saving some RAM. It also fixes a run-time bug
that mis-identifies IBM clones like the original Compaq Portable because their date code in BIOS doesn't perfectly match
what IBM did in the original IBM 5150 PC.  If you want to run the patch target then build the patch program first
by going to UTILS and running wmake.

## Forking and dependencies

If you are including mTCP in your project to use the TCP/IP library, consider using git submodules. Yes, you are
introducing a dependency but it will help keep you up to date, especially as the mTCP library changes and gets
fixes or new features. The API has been stable for years. See https://github.com/radozd/ftp2p for an example of
how to use mTCP as a submodule.

Forking is also a reasonable alternative - at least you can see the upstream changes when they happen.

## Support

I want you to have a great experience with mTCP and I provide support via email.  Please send your questions, bug reports
and feature requests to me to me at the email address listed above.  There is also a low-volume mailing list you can
subscribe to at https://groups.google.com/g/mtcp.

If you are running an older version of mTCP please try the latest version first before contacting me; your problem might
be a bug that has already been fixed.  You can use SERVICES.BAT to do a quick check to see if a new version is available
right from your DOS machine.

Don't understand the documentation?  That might be my fault.  Send me an email with your question and I'll try to make
it more clear.

Can't make it work?  There could be lots of reasons.  I try to explain the common problems in the PDF documentation.
If you have something that is truly uncommon and you are tired of banging your head on the wall send me an email.
There might be a bug or you might just need a gentle prod in the right direction.

 If you do ask for help via email please send me the following:

  * the version of mTCP you are running.
  * the class/type of hardware you are running on. (e.g.: Compaq Portable, PCjr, PS/2, DOSBox, generic Pentium, virtual machine, etc.)
  * the version of DOS you are using.
  * the details of your problem including what you think the problem is, what server you are connecting to, how to recreate the problem, etc.

If your problem is complex I may ask you to collect traces using the mTCP debug features.  Usually we can get to the bottom of the problem.

## My views on AI

This is my hobby project, and I do this for fun. As a result, I insist on doing my own work and I do not use AI
for any part of this project.

## Like what you see?  Want to say thanks?

Thank you!  I have never accepted any money, beer or cookies for my work. If you want to say thanks in a tangible way
I've never seen an animal shelter that was over-funded.

I also have mTCP stickers to hand out if you ever see me in person.
