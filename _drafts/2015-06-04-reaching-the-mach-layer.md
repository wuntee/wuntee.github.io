---
layout: post
title: Reaching the MACH layer
categories: osx mach xpc
tags: osx mach xpc
permalink: reaching-the-mach-layer
---

Background
----------
All of my research typically starts with a theory of how I can break something, or a point that I want to prove. This research all started with a general theory - I believe there are non-public IPC messages and protocols being used within Apple developed applications (and the core OS).

In order to examine this theory, I wanted to go as low-level as possible when examining the OSX IPC mechanism. There has been some minimal research done on OSX IPC, however I have not seen any go as low as the mach layer. Most research I have seen examines the XPC layer and above (more on how this all fits together later).


WTF is a mach?!
---------------
The obvious first question I had when attempting to prove/disprove my theory was - how does IPC work in OSX? The answer I received was roughly: "oh, through mach messages and XPC and IOKit" but thats about as much detail as I received. There is not a ton public information on the mach layer ([apple developer](https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/KernelProgramming/Mach/Mach.html), [outdated book](https://books.google.com/books?id=K8vUkpOXhN4C&lpg=PA1025&ots=OLkiTVUp1y&dq=osx%20ipc%20mach%20singhe&pg=PA1027#v=onepage&q&f=false), [sample code](http://nshipster.com/inter-process-communication/)), however there is source. OSX IPC is based on mach messaging, which are part of the XNU portion of the kernel, which is open source ([tarball](http://opensource.apple.com/tarballs/xnu/xnu-2782.1.97.tar.gz) - [github](https://github.com/opensource-apple/xnu)).

After reading over everything, and digging through the XNU source a bit, a few things stood out:

* Mach messages are sent via kernel [traps](https://www.youtube.com/watch?v=EmZvOhHF85I).
* The lowest function call, prior to calling the kernel trap, to send messages is the [`mach_msg`](https://github.com/opensource-apple/xnu/blob/bb7368935f659ada117c0889612e379c97eb83b3/libsyscall/mach/mach_msg.c#L80) function.
* Mach message source/destinations are referenced via "ports" which are just unsigned integers.
* Mach ports are process specific. IE: the mach port/integer for "networkd" in Chrome does not necessarily equal the same mach port/integer in Safari.
* Ports can be "looked up" similar to how DNS resolves a hostname to an IP address via `bootstrap`.
* In OSX, bootstrap is `launchd`.
* Applications register with launchd/bootstrap similar to `inted` on linux.
* The kernel is the source of truth for what mach port number represents what destination and visa versa. 
* Communication to `launchd`/bootstrap is performed via IPC.
* There are "special" ports that the kernel is aware of, and can be returned via function calls, without looking them up via bootstrap.
* Apple OSX IPC is moving towards using XPC as a transport framework.

Almost all IPC built-in to OSX is all based on mach messages. When someone says they are using IOKit, or XPC that all funnels down to eventually using mach messages to transmit data between applications. Mach and XPC have a similar relationship to IP and TCP. In IP/TCP, an IP packet has a structure with an arbitrary data payload. That arbitrary data payload can be of type TCP, which has its own structure. In mach/XPC, mach has a structure with an arbitrary data payload. XPC is the arbitrary payload within the mach message. More specifically, XPC is a general [de]serialization approach to transmit data.

The mach message structure is defined as [`mach_msg_header_t`](https://github.com/opensource-apple/xnu/blob/10.10/osfmk/mach/message.h#L401). The full message structure is as follows:

[![Mach message header structure]({{ site.url }}/resources/2015-06-04-reaching-the-mach-layer/mach_msg_header.jpg)]({{ site.url }}/resources/2015-06-04-reaching-the-mach-layer/mach_msg_header.jpg)
_Note: photo source - [http://flylib.com/books/en/3.126.1.104/1/](http://flylib.com/books/en/3.126.1.104/1/)_

One important thing about mach messages, that is only (that I am aware of) explained a comment in the [source](https://github.com/opensource-apple/xnu/blob/10.10/osfmk/mach/message.h#L197) is: 

{% highlight c %}

*  Every message starts with a message header.
*  Following the message header, if the message is complex, are a count
*  of type descriptors and the type descriptors themselves 
*  (mach_msg_descriptor_t). The size of the message must be specified in 
*  bytes, and includes the message header, descriptor count, descriptors, 
*  and inline data.
{% endhighlight %}

So, when examining a raw pointer to a message, you first have the `mach_msg_header_t` then `if MACH_MSGH_BITS_IS_COMPLEX(msg->msgh_bits) == true` there is an unsigned int with the number of descriptors, followed by the descriptors, followed by the raw data. If that IS_COMPLEX is false, there is just raw data following the `mach_msg_header_t`.

What does your mach look like?
------------------------------
Now that I thought that I kind of understood mach, I wanted to see something tangible - what does a mach transaction actually look like? My first hint was from the [NSHipster post](http://nshipster.com/inter-process-communication/) I referenced earlier, however that was more about creating a client/server interaction where I construct the message. This was a good start, but I wanted to see what other peoples mach's looked like. This is easier said than done...

My first thought was that since the kernel is the source of truth for this mach nonsense, lets whip up a kernel extension to print it all out, and we will be happy campers. The OSX kernel had different plans. After spending a couple of days on this, and only getting to the point of a "hello world" kernel extension, printing out to syslog, I decided this is probably not the best path forward. That being said, I did learn quite a few things:

* As of OSX 10.10.1 kernel extension signing is enforced. In order to bypass this, you must disable kernel extension signing in nvram (`sudo nvram boot-args=kext-dev-mode=1`) - I didn't want to do this on my main machine for security purposes, so all kernel dev was done on a VM. Very annoying. 
* Kernel extensions don't have the fancy schmacy libraries like normal applications do - for example, there is no `fopen`. Even more annoying.
* In order to export data, kernel extensions typically interact with a user-land application to do helpful things like.... write to files.... or print data to stdout.... This increases development overhead like 1000 times. At this point I was done with kernel extensions.

Ok, no more kernel extension, and this is where I almost gave up, until I realized that every IPC should/must filter through the `mach_msg` function. I knew Linux had the ability to perform function hooking via LD_PRELOAD, and discovered a similar concept exists in OSX via DYLD_INSERT_LIBRARIES.

The `mach_msg` is defined as follows:

{% highlight c %}
mach_msg_return_t
mach_msg(msg, option, send_size, rcv_size, rcv_name, timeout, notify)
	mach_msg_header_t *msg;
	mach_msg_option_t option;
	mach_msg_size_t send_size;
	mach_msg_size_t rcv_size;
	mach_port_t rcv_name;
	mach_msg_timeout_t timeout;
	mach_port_t notify;
{% endhighlight %}

And, the `mach_msg_header_t` structure is defined in the image in the previous section.

My thought was - if I can run an application, while hooking `mach_msg`, I can print the contents of the message to stdout. The following is a code stub to do this (note: 'hexdump' is not defined in the sample code);

{% highlight c %}
#include <dlfcn.h>
#include <xpc/xpc.h>

mach_msg_return_t (*orig_mach_msg)(mach_msg_header_t *, 
	mach_msg_option_t, mach_msg_size_t, 
	mach_msg_size_t, 
	mach_port_t, 
	mach_msg_timeout_t, 
	mach_port_t);

mach_msg_return_t mach_msg(mach_msg_header_t *msg, 
	mach_msg_option_t option, 
	mach_msg_size_t send_size, 
	mach_msg_size_t rcv_size, 
	mach_port_t rcv_name, 
	mach_msg_timeout_t timeout, 
	mach_port_t notify){

	if(!orig_mach_msg){
		orig_mach_msg = dlsym(RTLD_NEXT, "mach_msg");
	}
	
	// The mach message's local_port is how a response will be sent  
	// back. If this is set, we assume there will be a response.
	bool response = msg->msgh_local_port > 0;

	// Request
	hexdump(msg, send_size);
	mach_msg_return_t ret = mach_msg(msg, 
		option, 
		send_size, 
		rcv_size, 
		rcv_name, 
		timeout, 
		notify);
	
	// Response
	if(response){
		hexdump(msg, rcv_size);
	}

	return(ret);
}
{% endhighlight %}

Compile via `clang -arch x86_64 -arch i386 -Wall -o hook.dylib -dynamiclib hook.c` and it can run via:

{% highlight bash %}
DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=hook.dylib [COMMAND]
{% endhighlight %}

And voila - you should get some output. For example, running a command like `open .`, the first message looks something like this:

[![mach_shark]({{ site.url }}/resources/2015-06-04-reaching-the-mach-layer/mach_shark.png)]({{ site.url }}/resources/2015-06-04-reaching-the-mach-layer/mach_shark.png)

It seems as though the first thing the command does is trying to interact with `com.apple.CoreServices.coreservicesd` which would make sense. You can also see the string "!CPX" which looks like some magic header for an XPC serialized message.

You may also be wondering what the 'mach_shark' command is that I ran in the screenshot. I created a generalized tool to intercept IPC messages that will be available soon.

_Note: There are other functions used to send mach messages, like `mach_msg_send` which just calls `mach_msg`. I assumed that if I just hook `mach_msg`, my hook would be triggered when `mach_msg_send` was called, however that is not the case. You will have to hook all functions where the target application will be sending messages. I am not completely clear why, but I assume it has something to do with the fact that `mach_msg` and `mach_msg_send` are both located in libkernel.dyld, and the library doesn't have to look up the dynamic address based on name of the function, which is how the DYLD hook is triggered?_


Can I play with your mach
-------------------------
My next step was to attempt to replay a mach message. Now, I didn't give details about how the 'hexdump' function works above, but you can see it gives full details about how the mach message is constructed. There are many more variables than just the payload of the message (see [`mach_msg_header_t`](https://github.com/opensource-apple/xnu/blob/10.10/osfmk/mach/message.h#L401)), which affect how the message is transmitted from process A to process B. Specifically:

* How is IPC data transfered between process A and process B (copy, move, etc)
* Timeout
* Additional descriptors which can contain additional ports, out of line memory, etc
* Something about a voucher (which I still don't completely understand)
* Receiving port, for the response

The other thing to keep in mind is something I referenced above: Mach ports are process specific. IE: the mach port/uint that represents "networkd" in Chrome does not necessarily equal the same mach port/uint in Safari.

Fortunately, the first message displayed above is sent to `bootstrap` which can be directly queried by the function call `task_get_bootstrap_port`.

My first idea was to just simply cast the raw data of a message back to a `mach_msg_header_t` and call `mach_msg` on that pointer, however that triggered a failure (for still unknown reasons). What did end up working, though, was to cast the data to a `mach_msg_header_t` and then re-set that struct's variables.

The following snippet will successfully replay the message. However, since the message gets a response, this is only half of the conversation. 

{% highlight c %}
int main( int argc, const char* argv[] ){
	mach_port_t port, bp;
	kern_return_t ret = task_get_bootstrap_port(mach_task_self(), &bp);
	port = bp;
	unsigned char payload[] = {0x13, 0x15, 0x13, 0x80, 0x24, 0x01, 0x00, 0x00, 0x0b, 0x01, 0x00, 0x00, 0x0b, 0x02, 0x00, 0x00, 0x03, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x21, 0x43, 0x50, 0x58, 0x05, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0xec, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x73, 0x75, 0x62, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x75, 0x74, 0x69, 0x6e, 0x65, 0x00, 0x00, 0x40, 0x00, 0x00, 0xcf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x6c, 0x61, 0x67, 0x73, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x64, 0x00, 0x00, 0x00, 0x00, 0x74, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x70, 0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2d, 0x70, 0x6f, 0x72, 0x74, 0x00, 0x00, 0xd0, 0x00, 0x00};
	mach_msg_header_t *msg = (mach_msg_header_t *)payload;
	msg->msgh_remote_port = port;
	msg->msgh_local_port = MACH_PORT_NULL;
	msg->msgh_bits = MACH_MSGH_BITS_ZERO;
	msg->msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS_SET_PORTS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE, MACH_MSG_TYPE_COPY_SEND);
	mach_msg_return_t msg_ret = mach_msg_send(msg);
}
{% endhighlight %}

I have yet to examine the difference between the original message and whatever happens after I re-set the message attributes, but it made no difference to me, as I could now at least interact/replay messages at the mach layer. More importantly, start fuzzing message contents to bootstrap/launchd! A simple bit flipping fuzzer has led to about 5 unique crashes. I am still working on diagnosing two of the three, but will hopefully have a chance to give details out on the ones I have reported in my next post.

But, that's just launchd...
---------------------------
In the above example, we are only sending a message to `launchd`/bootstrap. This is the simplest of mach interactions because you can obtain the port number directly via the `task_get_bootstrap_port` function call. But, how do you send messages to other running daemons?!

This question makes everything much much much more complicated. When calling/hooking 'mach_send', the port information we have is `msg->msgh_remote_port`, or the unsigned int port number. Since port numbers are process independent (as I have mentioned a few times), we are unable to just take that port number and insert it in a message to replay the packet. We have to somehow look it up. This begs the following questions:

* Since we can't just insert the port number in the packet we are re-playing (since we are in a different process), how do we obtain the correct port for the service we want to talk to?
* How do we know exactly (string representation) what service the message is being sent to?

bootstrap_look_up
-----------------
Since `launchd` is like a resolution service for mach ports, there must be a way of utilizing it as such. This is done via the `bootstrap_look_up` function:

{% highlight c %}
mach_port_t port, bp;
kern_return_t ret = task_get_bootstrap_port(mach_task_self(), &bp);
ret = bootstrap_look_up(bp, "com.apple.CoreServices.coreservicesd", &port);
{% endhighlight %}

So, in order to get a port number, you must query bootstrap via a string representation of the port. Which leads to the next question. When hooking `mach_msg` how do I know what the string representation of the port is that the process is communicating with. I failed down this path many times, and will try to summarizer the attempts here:

* Kernel extension - Since the kernel is the source of truth for much of the IPC and port information, why don't we create an extension that I can look-up the PID/port_id and get back the string representation? Unfortunately, this is harder said than done. `launchd` is actually the process that contains the port string that is used to register the application and eventually the port_id. In the kernel, the most I would be able to obtain is the PID of the destination process (and in turn the binary location). This doesn't help, because `bootstrap_look_up` requires the 'com.apple.blah.blah' type name to look-up.
* `Launchctl print` - There is a nice method within `launchctl` that provides you exactly what I am looking for - the string representation to port_id mapping. You can see this by running the command `sudo launchctl print pid/[PID_HERE]`. I didn't want to execute an external command and parse stdout, so I started to reverse how `launchctl` does this. `launchctl` sends an XPC message to `launchd`, containing a file descriptor to stdout, which `launchd` ends up just printing the information directly to. FTS.
* MOAR HOOKING - Why not just hook `bootstrap_look_up` and keep a mapping of the lookups? This is the first thing that _kinda_ worked. Unfortunately, this is not the only way that ports are looked-up. After doing a bit more of reverse engineering on `launchctl` and some other Apple binaries, there are some other functions `bootstrap_look_up`, `bootstrap_look_up2`, `task_get_special_port`, and `bootstrap_register2`. This gives a bit more context into the port/string mapping if you intercept them, however there are still 75% of the messages with unknown port names.

One thing I was able to see, however, were additional XPC messages, which resembled lookup requests, however I was unable to find the origin function that was calling them. For example:

[![XPC port lookup]({{ site.url }}/resources/2015-06-04-reaching-the-mach-layer/xpc_lookup.png)]({{ site.url }}/resources/2015-06-04-reaching-the-mach-layer/xpc_lookup.png)

Note the 'lookup-handle' part of the request. Following that, the response contains a port descriptor (how ports are passed between processes via mach):

[![XPC port lookup response]({{ site.url }}/resources/2015-06-04-reaching-the-mach-layer/xpc_lookup_response.png)]({{ site.url }}/resources/2015-06-04-reaching-the-mach-layer/xpc_lookup_response.png)

__&lt;xpc teaser&gt;__

XPC is an abstraction layer to send data between processes via mach ports. The lowest level functions emulate a key/value store (getters/setters for different data types). XPC has additional functionality which allows for transferring more complex objects like port's/connections (`xpc_dictionary_set_connection`) as well as file descriptors (`xpc_dictionary_set_fd`) automatically. The way this is achieved, at the mach level, is including port descriptors in the XPC message. 

__&lt;/xpc teaser&gt;__

Since I didn't know the source function, and I knew I was going to dive deeper into XPC, I spend a lot of time reversing the XPC [de]serialization routines and incorporated lookup XPC payloads into the name/port mapping. Now, I was able to see the full context of the messages that go back and forth. However, it doesn't end there. Most interactions happen using XPC, and XPC is a bit more complicated that sending messages back and forth. Details on this will be in the following blog post.









