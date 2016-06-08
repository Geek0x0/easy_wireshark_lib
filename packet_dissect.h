#ifndef _PACKET_DISSECT_
#define _PACKET_DISSECT_

#define HAVE_STDARG_H 1
#define WS_MSVC_NORETURN
#define _GNU_SOURCE

//common
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <error.h>
//glib2.0         	-lglib-2.0
#include <glib/gtypes.h>
#include <glib/gslist.h>
//wireshark         -lwiretap -lwireshark -lwsutil
#include <config.h>
#include <epan/epan.h>
#include <epan/print.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/epan-int.h>
#include <wsutil/privileges.h>
#include <epan/epan_dissect.h>
#include <epan/proto.h>
#include <epan/ftypes/ftypes.h>
#include <epan/asm_utils.h>
#include <frame_tvbuff.h>
#include <wiretap/libpcap.h>
#include <color-shims.h>
#include <color_filters.h>
#include <color.h>

capture_file cfile;

typedef enum {
	dissect_to_psml = 1,
	dissect_to_pdml = 2,
	dissect_to_hex = 3,
} dissect_type;


typedef struct {
	dissect_type type;		/* type of dissect to data (psml/pdml/hex)  */
	capture_file cfile;		/* capture file struct for dissect (don't modify!!!) */
	frame_data fdata;		/* frame data struct for  dissect (don't modify!!!) */
} packet_dissect_t;

/**
 * get frame time
 * @param  data      [capture file struct pointer]
 * @param  frame_num [frame num]
 * @return           [success: nstime_t struct, error: NULL]
 */
static const nstime_t *
get_frame_ts(void *data, guint32 frame_num)
{
	capture_file *cf = (capture_file *) data;

	if (cf->ref && cf->ref->num == frame_num)
		return &(cf->ref->abs_ts);

	if (cf->prev_dis && cf->prev_dis->num == frame_num)
		return &(cf->prev_dis->abs_ts);

	if (cf->prev_cap && cf->prev_cap->num == frame_num)
		return &(cf->prev_cap->abs_ts);

	if (cf->frames) {
		frame_data *fd = frame_data_sequence_find(cf->frames, frame_num);

		return (fd) ? &fd->abs_ts : NULL;
	}

	return NULL;
}

/**
 * create new epan session struct
 * @return [epan struct pointer]
 */
static epan_t *create_new_epan_session(void)
{
	epan_t *epan = epan_new();
	epan->data = NULL;
	epan->get_frame_ts = get_frame_ts;
	epan->get_interface_name = NULL;
	epan->get_user_comment = NULL;

	return epan;
}

/**
 * init timestamp process
 */
inline static void init_timestamp(void)
{
	timestamp_set_type(TS_RELATIVE);
	timestamp_set_precision(TS_PREC_AUTO);
	timestamp_set_seconds_type(TS_SECONDS_DEFAULT);
}

/**
 * init wireshark epan module
 */
static void init_dissect_env(void)
{
	//1. initialize the environment
	init_process_policies();
	//2. init timestamp
	init_timestamp();
	//3. register all epan protocols handle
	epan_init(register_all_protocols,
	          register_all_protocol_handoffs, NULL, NULL);
	//4. init color filters
	color_filters_init();
}

/**
 * get dissect prefs
 */
inline static e_prefs *get_prefs(void)
{
	e_prefs *prefs_p;
	char *gpf_path, *pf_path;
	int gpf_read_errno, gpf_open_errno;
	int pf_open_errno, pf_read_errno;

	prefs_p = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
	                     &pf_open_errno, &pf_read_errno, &pf_path);
	return prefs_p;
}

/**
 * init capture file struct
 */
inline static void init_capture_file(capture_file *cf)
{
	memset(cf, 0, sizeof(capture_file));
	cf->snap = WTAP_MAX_PACKET_SIZE;
	cf->count = 0;
}

/**
 * create packet dissect handle
 * @param  type [type of parse to string]
 * @return      [packet dissect handle]
 */
static packet_dissect_t *
create_packet_dissetc_handle(const char *type_s)
{
	dissect_type type = 0;
	e_prefs *prefs_p;
	packet_dissect_t *handle = NULL;

	if (!strncmp(type_s, "psml", 4))
		type = dissect_to_psml;
	else if (!strncmp(type_s, "pdml", 4))
		type = dissect_to_pdml;
	else if (!strncmp(type_s, "hex", 3))
		type = dissect_to_hex;
	else {
		return handle;
	}

	if (!(handle = calloc(1, sizeof(packet_dissect_t))))
		return handle;
	handle->type = type;
	init_capture_file(&(handle->cfile));
	handle->cfile.epan = create_new_epan_session();
	handle->cfile.epan->data = &cfile;
	prefs_p = get_prefs();
	build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

	return handle;
}

/**
 * realase wireshark epan module
 */
static void release_epan_module()
{
	epan_cleanup();
}

/**
 * destroy packet dissect handle
 * @param h [packet dissect handle]
 */
static void
destroy_packet_dissect_handle(packet_dissect_t * h)
{

	if (h->cfile.frames != NULL)
	{
		free_frame_data_sequence(h->cfile.frames);
		h->cfile.frames = NULL;
	}

	if (h->cfile.wth != NULL)
	{
		wtap_close(h->cfile.wth);
		h->cfile.wth = NULL;
	}

	if (h->cfile.epan != NULL)
	{
		epan_free(h->cfile.epan);
		h->cfile.epan = NULL;
	}

	release_epan_module();
	free(h);
}

/**
 * create current dissect packet wtap pkt header
 * @param  data [packet with pcap packet header]
 * @param  w    [wtap header]
 */
inline static void create_wtap_pkthdr(void *data, struct wtap_pkthdr *w)
{
	struct pcaprec_hdr *pcap_phdr = (struct pcaprec_hdr *) data;

	memset(w, 0, sizeof(struct wtap_pkthdr));
	//fill wtap_pkthdr
	w->pkt_encap = WTAP_ENCAP_ETHERNET;
	w->len = pcap_phdr->incl_len;
	w->caplen = pcap_phdr->orig_len;
	w->pkt_tsprec = WTAP_TSPREC_USEC;
	w->ts.secs = pcap_phdr->ts_sec;
	w->ts.nsecs = pcap_phdr->ts_usec * 1000;
}

/**
 * use wireshark epan module to dissect packet
 * @param pkt     [packet data with pcap header]
 * @param pkt_len [packet data size]
 * @param id      [capture packet id]
 * @param cpd     [current packet dissect handle]
 * @param edt   [return packet epan info]
 */
static inline void
dissect_packet(void *pkt, uint16_t pkt_len, uint32_t id,
               packet_dissect_t *cpd, epan_dissect_t **edt_p)
{
	epan_dissect_t *edt = NULL;
	struct wtap_pkthdr whdr;

//1. create current packet wtap pkthdr
	create_wtap_pkthdr(pkt, &whdr);
//2. init packet frame
	frame_data_init(&(cpd->fdata), id, &whdr, 0, 0);
//3. create new dissect epan
	edt = epan_dissect_new(cpd->cfile.epan, TRUE, TRUE);
//4. enable color fiters for dissect epan
	color_filters_prime_edt(edt);
//5. before dissect set frame data
	frame_data_set_before_dissect(&(cpd->fdata), &(cpd->cfile.elapsed_time),
	                              &cfile.ref, cfile.prev_dis);
//6. dissect packet action
	pkt = pkt + sizeof(struct pcaprec_hdr);
	epan_dissect_run(edt, 0, &(cfile.phdr), frame_tvbuff_new(&(cpd->fdata), pkt),
	                 &(cpd->fdata), &cfile.cinfo);
//7. fill color filters data
	edt->pi.fd->color_filter = color_filters_colorize_packet(edt);
//8. destory frame memory
	frame_data_destroy(&(cpd->fdata));
//9. fill dissect data to colums
	epan_dissect_fill_in_columns(edt, FALSE, TRUE);

	*edt_p = edt;
}

/**
 * switch memory to file pointer(fprintf can use it)
 * @param  mem  [memory head point]
 * @param  size [memory size]
 * @return      [success: file pointer, error: NULL]
 */
inline static
FILE *mem_to_file_pointer(void *mem, uint16_t size)
{
	return fmemopen(mem, size, "w");
}

/**
 * remove substring(can use to remove wrap)
 * @param s        [input string]
 * @param toremove [remove sub string]
 */
inline static void remove_substring(char *s, const char *toremove)
{
	while ((s = strstr(s, toremove)))
		memmove(s, (s + strlen(toremove)),
		        (1 + strlen(s + strlen(toremove))));
}

/**
 * dissect packet data to string
 * @param  cpd       [currect dissect packet handle]
 * @param  pkt       [packet data with pcap pakcet hdr]
 * @param  pkt_len   [packet real data len]
 * @param  pkt_id    [capture packet id]
 * @param  data      [set resault data buffer]
 * @param  data_size [resault buffer size]
 * @return           [success: TRUE, error: FALSE]
 */
inline static int
dissect_packet_to_data(packet_dissect_t *cpd, void *pkt, uint16_t pkt_len,
                       uint32_t pkt_id, void *data, uint32_t data_size)
{
	epan_dissect_t *edt = NULL;
	print_stream_t *print_stream = NULL;

//!must check param
	if (!cpd && !pkt && !pkt_len && !data && !data_size)
		return FALSE;

//1. switch memory to file pointer
	FILE * fmem = mem_to_file_pointer(data, data_size);
	if (!fmem)
	{
		fprintf(stderr,
		        "switch memory to file pointer error\n");
		return FALSE;
	}
//2. dissect packet
	dissect_packet(pkt, pkt_len, pkt_id, cpd, &edt);
	if (!edt)
	{
		fprintf(stderr, "dissect packet error\n");
		return FALSE;
	}
//3. output resault data to buffer
	switch (cpd->type)
	{
		case dissect_to_psml:	/* psml xml string */
			write_psml_columns(edt, fmem);
			break;
		case dissect_to_pdml:	/* pdml xml string */
			write_pdml_proto_tree(edt, fmem);
			break;
		case dissect_to_hex:	/* hex string */
			print_stream = print_stream_text_stdio_new(fmem);
			print_hex_data(print_stream, edt);
			break;
	}
	fclose(fmem); //buffer fflush(data fill to memory)
//4. remove all wrap
	remove_substring(data, "\n");
//5. free epan memory
	epan_dissect_free(edt);

	return TRUE;
}

#endif
