#include "link.h"
#include "switchview_proto.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <linux/hidraw.h>

#define KEEPALIVE_MS 20   // 50 Hz state refresh while idle
#define PING_MS 500       // link-health probe interval
#define UP_TIMEOUT_MS 2000
#define RESOCKET_MS 5000  // no echo for this long: rebuild the socket (interface may have changed)
#include <errno.h>
#include <fcntl.h>

// Text pacing: the firmware types ~10 chars/s from a 255-byte queue. A token
// bucket lets single keystrokes go out instantly while long pastes never
// overflow the Pico's queue.
#define TEXT_BUCKET_MAX 200.0f

// The board's "Pad Bridge Link" USB HID (the RP2350 firmware's PC link).
#define LINK_USB_VID 0x2E8A
#define LINK_USB_PID 0x400B
// Our USB link framing: the 33-byte sv_packet rides in the HID feature report,
// with a rolling sequence byte appended so the polled firmware sees new packets.
#define LINK_SV_SEQ_OFFSET 33

struct link {
  int fd;
  int usb;            // 1 = USB HID transport (hidraw), 0 = UDP
  uint8_t seq;        // rolling sequence for the USB framing
  uint32_t last_ok_ms; // last successful USB write (for link-up in USB mode)
  char usb_path[64];  // hidraw path, for reopen after a drop
  struct sockaddr_in dst;
  char desc[96];
  struct link_state cur;
  int dirty;
  uint32_t last_state_ms, last_text_ms, last_ping_ms, last_echo_ms, last_resocket_ms;
  float tokens;
  int mdx, mdy, mwheel, mdirty;
  unsigned mbtn;
  char textq[1024];
  unsigned tq_head, tq_tail;
  struct link_stats st;
};

static int open_socket(void)
{
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd >= 0) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  return fd;
}

// Find the board's Pad Bridge Link hidraw node by VID:PID. Returns 1 and fills
// `out` with e.g. "/dev/hidraw11", else 0.
static int find_hidraw_link(char *out, size_t n)
{
  DIR *d = opendir("/sys/class/hidraw");
  if (!d) return 0;
  struct dirent *e;
  int found = 0;
  char want[20];
  snprintf(want, sizeof want, "%04X:%04X", LINK_USB_VID, LINK_USB_PID);
  while (!found && (e = readdir(d))) {
    if (strncmp(e->d_name, "hidraw", 6) != 0) continue;
    char p[300];
    snprintf(p, sizeof p, "/sys/class/hidraw/%s/device/uevent", e->d_name);
    FILE *f = fopen(p, "r");
    if (!f) continue;
    char line[256];
    while (fgets(line, sizeof line, f)) {
      for (char *c = line; *c; c++) *c = (char)toupper((unsigned char)*c);
      // uevent HID_ID line looks like 0003:00002E8A:0000400B
      char v[8], pid[8];
      snprintf(v, sizeof v, "%04X", LINK_USB_VID);
      snprintf(pid, sizeof pid, "%04X", LINK_USB_PID);
      if (strstr(line, v) && strstr(line, pid)) { found = 1; break; }
    }
    fclose(f);
    if (found) snprintf(out, n, "/dev/%s", e->d_name);
  }
  closedir(d);
  (void)want;
  return found;
}

// Open the board over USB. `spec` is "usb" (auto-find) or "usb:/dev/hidrawN".
static int link_open_usb(struct link *l, const char *spec)
{
  char path[64];
  if (spec[3] == ':' && spec[4]) {
    snprintf(path, sizeof path, "%s", spec + 4);
  } else if (!find_hidraw_link(path, sizeof path)) {
    fprintf(stderr, "link: no board USB link (%04X:%04X) found; is the PIO/USB-A "
                    "cable in the PC and the composite firmware flashed?\n",
            LINK_USB_VID, LINK_USB_PID);
    return -1;
  }
  int fd = open(path, O_RDWR);
  if (fd < 0) {
    fprintf(stderr, "link: open %s: %s (install linux/99-switch-pad.rules?)\n",
            path, strerror(errno));
    return -1;
  }
  l->fd = fd;
  l->usb = 1;
  snprintf(l->usb_path, sizeof l->usb_path, "%s", path);
  snprintf(l->desc, sizeof l->desc, "usb %s", path);
  return 0;
}

struct link *link_open(const char *host, int port)
{
  struct link *l = calloc(1, sizeof *l);
  l->cur.hat = SV_HAT_CENTER;
  l->dirty = 1;
  l->tokens = TEXT_BUCKET_MAX;
  l->st.leds = -1;

  if (strncmp(host, "usb", 3) == 0) {
    if (link_open_usb(l, host) < 0) { free(l); return NULL; }
    return l;
  }

  l->fd = open_socket();
  if (l->fd < 0) { perror("socket"); free(l); return NULL; }
  l->dst.sin_family = AF_INET;
  l->dst.sin_port = htons((uint16_t)port);
  if (inet_pton(AF_INET, host, &l->dst.sin_addr) != 1) {
    fprintf(stderr, "link: bad host %s\n", host);
    close(l->fd);
    free(l);
    return NULL;
  }
  snprintf(l->desc, sizeof l->desc, "udp %s:%d", host, port);
  return l;
}

void link_close(struct link *l)
{
  if (!l) return;
  // Leave the Switch with everything released.
  struct link_state zero = {.hat = SV_HAT_CENTER};
  link_set_state(l, &zero);
  link_poll(l, l->last_state_ms + KEEPALIVE_MS + 1);
  close(l->fd);
  free(l);
}

static void send_packet(struct link *l, const sv_packet *p)
{
  if (l->usb) {
    if (l->fd < 0) { l->st.send_errors++; return; }
    uint8_t buf[65];                             // [0] report id 0 + 64 payload
    memset(buf, 0, sizeof buf);
    memcpy(buf + 1, p, SV_PACKET_SIZE);          // the 33-byte sv_packet
    buf[1 + LINK_SV_SEQ_OFFSET] = ++l->seq;      // rolling seq for the polled firmware
    if (ioctl(l->fd, HIDIOCSFEATURE(sizeof buf), buf) < 0) {
      l->st.send_errors++;
      if (errno == ENODEV || errno == EIO) { close(l->fd); l->fd = -1; } // dropped; poll reopens
    } else {
      l->st.packets++;
    }
    return;
  }
  if (sendto(l->fd, p, SV_PACKET_SIZE, MSG_DONTWAIT, (struct sockaddr *)&l->dst, sizeof l->dst) < 0)
    l->st.send_errors++;
  else
    l->st.packets++;
}

void link_set_state(struct link *l, const struct link_state *s)
{
  if (memcmp(&l->cur, s, sizeof *s) == 0) return;
  l->cur = *s;
  l->dirty = 1;
}

void link_mouse(struct link *l, int dx, int dy, int wheel, unsigned buttons)
{
  l->mdx += dx; l->mdy += dy; l->mwheel += wheel;
  if (buttons != l->mbtn) { l->mbtn = buttons; l->mdirty = 1; }
  if (dx || dy || wheel) l->mdirty = 1;
}

void link_send_text(struct link *l, const char *text)
{
  for (; *text; text++) {
    unsigned next = (l->tq_head + 1) % sizeof l->textq;
    if (next == l->tq_tail) break;
    l->textq[l->tq_head] = *text;
    l->tq_head = next;
  }
}

void link_poll(struct link *l, uint32_t now_ms)
{
  if (l->dirty || now_ms - l->last_state_ms >= KEEPALIVE_MS) {
    sv_packet p = {.magic = {SV_MAGIC0, SV_MAGIC1}, .type = SV_PKT_STATE,
                   .buttons = l->cur.buttons, .lx = l->cur.lx, .ly = l->cur.ly,
                   .rx = l->cur.rx, .ry = l->cur.ry, .hat = l->cur.hat};
    send_packet(l, &p);
    l->dirty = 0;
    l->last_state_ms = now_ms;
    l->st.last_send_ms = now_ms;
  }

  if (l->mdirty) {
    int cl = l->mdx < -32767 ? -32767 : l->mdx > 32767 ? 32767 : l->mdx;
    int cy = l->mdy < -32767 ? -32767 : l->mdy > 32767 ? 32767 : l->mdy;
    int cw = l->mwheel < -127 ? -127 : l->mwheel > 127 ? 127 : l->mwheel;
    sv_packet p = {.magic = {SV_MAGIC0, SV_MAGIC1}, .type = SV_PKT_MOUSE, .buttons = l->mbtn,
                   .lx = (int16_t)cl, .ly = (int16_t)cy, .rx = (int16_t)cw, .hat = SV_HAT_CENTER};
    send_packet(l, &p);
    l->mdx -= cl; l->mdy -= cy; l->mwheel -= cw;
    l->mdirty = 0;
  }

  l->tokens += (now_ms - l->last_text_ms) * (SV_TEXT_CHARS_PER_SEC / 1000.0f);
  if (l->tokens > TEXT_BUCKET_MAX) l->tokens = TEXT_BUCKET_MAX;
  l->last_text_ms = now_ms;
  if (l->tq_head != l->tq_tail && l->tokens >= 1.0f) {
    sv_packet p = {.magic = {SV_MAGIC0, SV_MAGIC1}, .type = SV_PKT_TEXT, .hat = SV_HAT_CENTER};
    while (p.length < SV_TEXT_MAX && l->tq_head != l->tq_tail && l->tokens >= 1.0f) {
      p.text[p.length++] = (uint8_t)l->textq[l->tq_tail];
      l->tq_tail = (l->tq_tail + 1) % sizeof l->textq;
      l->tokens -= 1.0f;
    }
    send_packet(l, &p);
    l->st.last_send_ms = now_ms;
  }
  l->st.text_queued = (l->tq_head + sizeof l->textq - l->tq_tail) % sizeof l->textq;

  // Link health.
  if (l->usb) {
    // USB: "up" = the hidraw is open. A failed write (unplug) closes it; try to
    // re-find and reopen it periodically, since a replug may renumber hidrawN.
    if (l->fd < 0 && now_ms - l->last_resocket_ms >= RESOCKET_MS) {
      l->last_resocket_ms = now_ms;
      char path[64];
      if (find_hidraw_link(path, sizeof path)) {
        int fd = open(path, O_RDWR);
        if (fd >= 0) { l->fd = fd; snprintf(l->usb_path, sizeof l->usb_path, "%s", path); }
      }
    }
    int up = l->fd >= 0;
    if (up != l->st.up) fprintf(stderr, "link: board %s\n", up ? "connected" : "not responding (replug the PIO/USB-A cable)");
    l->st.up = up;
    return;
  }

  // UDP: ping, read echoes, and rebuild the socket if the Pico has gone quiet
  // for a while (covers the PC changing networks underneath us).
  if (now_ms - l->last_ping_ms >= PING_MS) {
    sv_packet p = {.magic = {SV_MAGIC0, SV_MAGIC1}, .type = SV_PKT_PING, .buttons = now_ms,
                   .hat = SV_HAT_CENTER};
    send_packet(l, &p);
    l->last_ping_ms = now_ms;
  }
  sv_packet in;
  struct sockaddr_in from;
  socklen_t fl = sizeof from;
  while (recvfrom(l->fd, &in, sizeof in, MSG_DONTWAIT, (struct sockaddr *)&from, &fl) >= SV_PACKET_SIZE) {
    if (in.magic[0] == SV_MAGIC0 && in.magic[1] == SV_MAGIC1 && in.type == SV_PKT_PING) {
      l->last_echo_ms = now_ms;
      l->st.rtt_ms = (float)(now_ms - in.buttons);
      l->st.leds = in.text[1] ? in.text[0] : -1;
    }
  }
  int up = l->last_echo_ms && now_ms - l->last_echo_ms < UP_TIMEOUT_MS;
  if (up != l->st.up) fprintf(stderr, "link: Pico %s\n", up ? "up" : "not answering");
  l->st.up = up;
  if (!up && now_ms - l->last_resocket_ms >= RESOCKET_MS) {
    int fd = open_socket();
    if (fd >= 0) { close(l->fd); l->fd = fd; }
    l->last_resocket_ms = now_ms;
  }
}

void link_get_stats(struct link *l, struct link_stats *out) { *out = l->st; }
const char *link_describe(struct link *l) { return l->desc; }
