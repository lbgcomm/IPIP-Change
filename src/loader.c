#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <linux/types.h>
#include <time.h>
#include <getopt.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <fcntl.h>

#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>

#include <bpf.h>
#include <libbpf.h>

#include "loader.h"

// Other variables.
static __u8 cont = 1;
void signalHndl(int tmp)
{
    cont = 0;
}

const struct option opts[] =
{
    {"dev", required_argument, NULL, 'd'},
    {NULL, 0, NULL, 0}
};

void parsecommandline(struct cmdline *cmd, int argc, char *argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "d:", opts, NULL)) != -1)
    {
        switch (c)
        {
            case 'd':
                cmd->interface = optarg;

                break;

            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}

/**
 * Loads a BPF object file.
 * 
 * @param filename The path to the BPF object file.
 * 
 * @return BPF's program FD.
*/
int loadbpfobj(const char *filename, __u8 offload, int ifidx)
{
    int fd = -1;

    // Create attributes and assign XDP type + file name.
    struct bpf_prog_load_attr attrs = 
    {
		.prog_type = BPF_PROG_TYPE_XDP,
	};

    // If we want to offload the XDP program, we must send the ifindex item to the interface's index.
    if (offload)
    {
        attrs.ifindex = ifidx;
    }
    
    attrs.file = filename;

    // Check if we can access the BPF object file.
    if (access(filename, O_RDONLY) < 0) 
    {
        fprintf(stderr, "Could not read/access BPF object file :: %s (%s).\n", filename, strerror(errno));

        return fd;
    }

    struct bpf_object *obj = NULL;
    int err;

    // Load the BPF object file itself.
    err = bpf_prog_load_xattr(&attrs, &obj, &fd);

    if (err) 
    {
        fprintf(stderr, "Could not load XDP BPF program :: %s.\n", strerror(errno));

        return fd;
    }

    struct bpf_program *prog;

    // Load the BPF program itself by section name and try to retrieve FD.
    prog = bpf_object__find_program_by_title(obj, "xdp_prog");
    fd = bpf_program__fd(prog);

    if (fd < 0) 
    {
        printf("XDP program not found by section/title :: xdp_prog (%s).\n", strerror(fd));

        return fd;
    }

    return fd;
}

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param ifidx The index to the interface to attach to.
 * @param progfd A file description (FD) to the BPF/XDP program.
 * @param cmd A pointer to a cmdline struct that includes command line arguments (mostly checking for offload/HW mode set).
 * 
 * @return Returns the flag (int) it successfully attached the BPF/XDP program with or a negative value for error.
 */
int attachxdp(int ifidx, int progfd, struct cmdline *cmd)
{
    int err;

    char *smode;

    __u32 flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    __u32 mode = XDP_FLAGS_DRV_MODE;

    smode = "DRV/native";

    if (cmd->offload)
    {
        smode = "HW/offload";

        mode = XDP_FLAGS_HW_MODE;
    }
    else if (cmd->skb)
    {
        smode = "SKB/generic";
        mode = XDP_FLAGS_SKB_MODE;
    }

    flags |= mode;

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        err = bpf_set_link_xdp_fd(ifidx, progfd, flags);

        if (err || progfd == -1)
        {
            const char *errmode;

            // Decrease mode.
            switch (mode)
            {
                case XDP_FLAGS_HW_MODE:
                    mode = XDP_FLAGS_DRV_MODE;
                    flags &= ~XDP_FLAGS_HW_MODE;
                    errmode = "HW/offload";

                    break;

                case XDP_FLAGS_DRV_MODE:
                    mode = XDP_FLAGS_SKB_MODE;
                    flags &= ~XDP_FLAGS_DRV_MODE;
                    errmode = "DRV/native";

                    break;

                case XDP_FLAGS_SKB_MODE:
                    // Exit program and set mode to -1 indicating error.
                    exit = 1;
                    mode = -err;
                    errmode = "SKB/generic";

                    break;
            }

            if (progfd != -1)
            {
                fprintf(stderr, "Could not attach with %s mode (%s)(%d).\n", errmode, strerror(-err), err);
            }
            
            if (mode != -err)
            {
                smode = (mode == XDP_FLAGS_HW_MODE) ? "HW/offload" : (mode == XDP_FLAGS_DRV_MODE) ? "DRV/native" : (mode == XDP_FLAGS_SKB_MODE) ? "SKB/generic" : "N/A";
                flags |= mode;
            }
        }
        else
        {
            fprintf(stdout, "Loaded XDP program in %s mode.\n", smode);

            break;
        }
    }

    return mode;
}

int main(int argc, char *argv[])
{
    // Parse the command line.
    struct cmdline cmd = {0};
    parsecommandline(&cmd, argc, argv);

    if (cmd.interface == NULL)
    {
        fprintf(stderr, "Interface not defined in command line.\n");
    }

    // Raise RLimit.
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &rl)) 
    {
        fprintf(stderr, "Error setting rlimit.\n");

        return EXIT_FAILURE;
    }

    // Get device.
    int ifidx;

    if ((ifidx = if_nametoindex(cmd.interface)) < 0)
    {
        fprintf(stderr, "Error finding device %s.\n", cmd.interface);

        return EXIT_FAILURE;
    }

    // XDP variables.
    int progfd;
    const char *filename = "/etc/ipip_changer/xdp.o";

    // Get XDP's ID.
    progfd = loadbpfobj(filename, cmd.offload, ifidx);

    if (progfd <= 0)
    {
        fprintf(stderr, "Error loading eBPF object file. File name => %s.\n", filename);

        return EXIT_FAILURE;
    }
    
    // Attach XDP program.
    int res = attachxdp(ifidx, progfd, &cmd);

    if (res != XDP_FLAGS_HW_MODE && res != XDP_FLAGS_DRV_MODE && res != XDP_FLAGS_SKB_MODE)
    {
        fprintf(stderr, "Error attaching XDP program :: %s (%d)\n", strerror(res), res);

        return EXIT_FAILURE;
    }

    // Signal.
    signal(SIGINT, signalHndl);

    while (cont)
    {
        sleep(1);
    }

    // Detach XDP program.
    attachxdp(ifidx, -1, &cmd);

    // Add spacing.
    fprintf(stdout, "\n");

    // Exit program successfully.
    return EXIT_SUCCESS;
}