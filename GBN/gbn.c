#include "gbn.h"

// Coding by Nina Wang(nw364) & Guangwei Jiang(gj94) 

state_t s = {.current_state = CLOSED, .expected_seqnum = 0};

volatile sig_atomic_t e_flag = false;

void timeout_handler(int signum)
{
	printf("Call timeout handler\n");
	e_flag = true;
}

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags) {
    size_t sent_bytes = 0;
    int window_size = 1;
    uint8_t next_seq_num = s.seq_num; // Next sequence number to send
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = timeout_handler;
    sigaction(SIGALRM, &sa, NULL);

    printf("Starting transmission with window size: %d\n", window_size);

    while (sent_bytes < len) {
        int packets_sent = 0;
        printf("Current window size: %d\n", window_size);

        for (int i = 0; i < window_size && sent_bytes < len; i++) {
            size_t chunk_size = len - sent_bytes > DATALEN ? DATALEN : len - sent_bytes;
            gbnhdr data_packet;
            memset(&data_packet, 0, sizeof(gbnhdr));
            data_packet.type = DATA;
            data_packet.seqnum = next_seq_num++;
            memcpy(data_packet.data, (char *)buf + sent_bytes, chunk_size);
            data_packet.checksum = checksum((uint16_t *)&data_packet, sizeof(gbnhdr) / 2);

            if (maybe_sendto(sockfd, &data_packet, sizeof(gbnhdr), flags, (struct sockaddr *)&s.remote_addr, s.remote_addr_len) < 0) {
                perror("Error sending data packet");
                return -1;
            }
            sent_bytes += chunk_size;
            packets_sent++;
            printf("Packet %d sent, total sent bytes: %zu\n", data_packet.seqnum, sent_bytes);
        }

        int acks_received = 0;
        while (acks_received < packets_sent) {
			// Set an alarm to wait for ACKs
            alarm(TIMEOUT);
            gbnhdr ack_packet;
            struct sockaddr from;
            socklen_t fromlen = sizeof(from);
            if (maybe_recvfrom(sockfd, &ack_packet, sizeof(gbnhdr), 0, &from, &fromlen) < 0 && errno != EINTR) {
                perror("Error receiving ACK");
                return -1;
            }

            if (e_flag) {
                printf("Timeout occurred, decreasing window size. Current window size: %d\n", window_size);
                e_flag = false; // Reset the flag
                window_size = (window_size / 2) > 1 ? (window_size / 2) : 1; // Decrease window size on timeout
                sent_bytes -= DATALEN * packets_sent; // Rollback sent_bytes to resend packets
                next_seq_num -= packets_sent; // Reset sequence number to resend packets
                
				// Break from ACK waiting loop to resend packets
				break; 
				
            } else if (ack_packet.type == DATAACK && ack_packet.seqnum == (next_seq_num - packets_sent + acks_received) % 256) {
                acks_received++;
                printf("ACK received for packet %d, increasing acks_received to %d\n", ack_packet.seqnum, acks_received);
            }
        }

        if (acks_received == packets_sent) {
            printf("All packets in the window acknowledged, increasing window size. New window size: %d\n", window_size + 1);
            window_size = (window_size + 1) < MAX_WINDOW_SIZE ? (window_size + 1) : MAX_WINDOW_SIZE; // Increase window size
        }
    }

    alarm(0); // Cancel any pending alarm
    printf("Transmission completed. Total sent bytes: %zu\n", sent_bytes);
    return sent_bytes; // Return the total number of bytes sent successfully
}



ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags) {
    struct sockaddr from;
    socklen_t fromlen = sizeof(from);
    gbnhdr recv_packet;

    while (true) {
        memset(&recv_packet, 0, sizeof(recv_packet));
        ssize_t packet_len = maybe_recvfrom(sockfd, &recv_packet, sizeof(recv_packet), flags, &from, &fromlen);

		printf("Recv one more time: \n");
		printf("Expected: %d, Received: %d\n", s.expected_seqnum, recv_packet.seqnum);

        if (packet_len < 0) {
            if (errno == EINTR) {
                // If recvfrom was interrupted by a signal, print a message and retry receiving
                printf("Reception interrupted by signal, retrying...\n");
                continue;
            } else {
                // If recvfrom failed for reasons other than an interrupt, print an error and exit
                perror("Error receiving packet\n");
                return -1;
            }
        }


        uint16_t received_checksum = recv_packet.checksum;
        recv_packet.checksum = 0; // Zero checksum field to compute checksum of the rest
        uint16_t computed_checksum = checksum((uint16_t*)&recv_packet, sizeof(recv_packet)/2);

        // if (received_checksum != computed_checksum) {
        //     fprintf(stderr, "Checksum mismatch, packet possibly corrupted.\n");
        //     // Optionally, you might want to send a NACK or simply ignore this packet
        //     continue; // Skip processing this packet
        // }

        if (recv_packet.type == DATA && recv_packet.seqnum == s.expected_seqnum) {
            memcpy(buf, recv_packet.data, DATALEN); 
            s.expected_seqnum++; // Prepare for the next expected sequence number

            // Send an ACK for this packet.
            gbnhdr ack_packet;
            memset(&ack_packet, 0, sizeof(ack_packet));
            ack_packet.type = DATAACK;
            ack_packet.seqnum = recv_packet.seqnum;
            ack_packet.checksum = checksum((uint16_t*)&ack_packet, sizeof(ack_packet)/2);
            if (sendto(sockfd, &ack_packet, sizeof(ack_packet), 0, &from, fromlen) < 0) {
                perror("Error sending ACK\n");
                return -1;
            }
            break; // Exit the loop since packet was processed successfully
        } else {
            // Handle unexpected packet types or sequence numbers
            fprintf(stderr, "Unexpected packet type or sequence number. Expected: %d, Received: %d\n",
                    s.expected_seqnum, recv_packet.seqnum);
            
            continue; 
        }
    }
    return DATALEN; // Return the amount of data processed from the packet
}


int gbn_close(int sockfd)
{

	/* TODO: Your code here. */
	if (sockfd >= 0)
	{
		// Close the socket
		if (close(sockfd) < 0)
		{
			perror("Error closing socket\n");
			return -1;
		}
		// Reset the state
		s.current_state = CLOSED;
		printf("Connection closed.\n");
	}
	return 0;
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen)
{
	/* TODO: Your code here. */
	s.current_state = CLOSED;
	s.seq_num = 0;

	// server create socket and send (receive the sending data in syn_packet )
	gbnhdr syn_packet = {.type = SYN, .seqnum = 0, .checksum = 0};

	// Include data for checksum calculation
	syn_packet.checksum = checksum((uint16_t *)&syn_packet, sizeof(gbnhdr) / 2);

	printf("Sending SYN packet..wow\n");
	s.current_state = SYN_SENT;
	if (sendto(sockfd, &syn_packet, sizeof(syn_packet), 0, server, socklen) < 0)
	{
		perror("sendto SYN");
		return -1;
	}

	printf("successfully sent SYN, and timeout setting for SYN.\n");
	// timeout setting for SYN
	alarm(TIMEOUT);

	// server send back SYNACK
	gbnhdr synack_packet;
	struct sockaddr from;
	socklen_t fromlen = sizeof(from);

	// Attempt to receive a SYNACK packet
	if (recvfrom(sockfd, &synack_packet, sizeof(synack_packet), 0, &from, &fromlen) < 0)
	{
		perror("recvfrom SYNACK\n");
		return -1;
	}

	// Check if the received packet is a SYNACK
	if (synack_packet.type == SYNACK)
	{
		printf("Received SYNACK, connection established.\n");
		s.current_state = ESTABLISHED;
		memcpy(&s.remote_addr, server, sizeof(struct sockaddr));
		s.remote_addr_len = socklen;
		return 0;
	}
	else
	{
		fprintf(stderr, "Expected SYNACK, received different packet type.\n");
		return -1;
	}

	
	return 0;
}

int gbn_listen(int sockfd, int backlog)
{

	/* TODO: Your code here. */
	
	if (sockfd < 0)
	{
		fprintf(stderr, "Invalid socket file descriptor.\n");
		return -1; // Indicate error
	}

	printf("Server is ready to receive SYN packets.\n");

	// In actual implementation, you might initialize variables, set up signal handlers for timeouts, or perform other preparatory tasks here.

	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen)
{

	/* TODO: Your code here. */
	if (bind(sockfd, server, socklen) == -1)
	{
		perror("Error binding socket to address\n");
		return -1; // Return error on failure
	}
	return 0; // Return success on successful binding
}

int gbn_socket(int domain, int type, int protocol)
{

	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

	if (type != SOCK_DGRAM)
	{
		fprintf(stderr, "GBN protocol requires UDP. Invalid socket type.\n");
		return -1; // Return error if the socket type is not SOCK_DGRAM
	}

	signal(SIGALRM, timeout_handler);
	siginterrupt(SIGALRM, 1);

	/* TODO: Your code here. */
	int sockfd = socket(domain, SOCK_DGRAM, protocol);
	if (sockfd < 0)
	{
		perror("Error creating socket\n");
		return -1;
	}
	else
	{
		s.sockfd = sockfd; // Update the global state (if this design fits your implementation)
	}

	return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen)
{

	/* TODO: Your code here. */
	// Wait for SYN packet
	gbnhdr syn_pkt;
	if (recvfrom(sockfd, &syn_pkt, sizeof(syn_pkt), 0, client, socklen) < 0)
	{
		perror("Error receiving SYN packet");
		return -1;
	}

	// Check for SYN packet type
	if (syn_pkt.type != SYN)
	{
		fprintf(stderr, "Expected SYN, received different packet type.\n");
		return -1;
	}

	// Prepare and send SYNACK packet in response
	gbnhdr synack_pkt = {.type = SYNACK, .seqnum = 0, .checksum = 0};
	// Calculate checksum for SYNACK packet, similar to gbn_connect
	synack_pkt.checksum = checksum((uint16_t *)&synack_pkt, sizeof(gbnhdr) / 2);

	if (sendto(sockfd, &synack_pkt, sizeof(synack_pkt), 0, client, *socklen) < 0)
	{
		perror("Error sending SYNACK packet\n");
		return -1;
	}
	else
	{
		// Use timeout and handshake counter to avoid lost ACK hanging the loop
		alarm(TIMEOUT);
		// attempts++;
	}

	printf("SYN received and SYNACK sent.\n");
	return sockfd; // Successful "acceptance"
}

ssize_t maybe_recvfrom(int s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{

	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB * RAND_MAX)
	{

		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB * RAND_MAX)
		{
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len - 1) * rand() / (RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buf[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buf[index] = c;
		}

		return retval;
	}
	/*----- Packet lost -----*/
	return (len); /* Simulate a success */
}

ssize_t maybe_sendto(int s, const void *buf, size_t len, int flags,
					 const struct sockaddr *to, socklen_t tolen)
{

	char *buffer = malloc(len);
	memcpy(buffer, buf, len);

	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB * RAND_MAX)
	{
		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB * RAND_MAX)
		{

			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len - 1) * rand() / (RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buffer[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buffer[index] = c;
		}

		/*----- Sending the packet -----*/
		int retval = sendto(s, buffer, len, flags, to, tolen);
		free(buffer);
		return retval;
	}
	/*----- Packet lost -----*/
	else
		return (len); /* Simulate a success */
}
