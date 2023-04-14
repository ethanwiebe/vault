// Clip Library
// Copyright (c) 2018-2022 David Capello
//
// This file is released under the terms of the MIT license.
// Read LICENSE.txt for more information.

#include <xcb/xcb.h>

#include <atomic>
#include <algorithm>
#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#define CLIP_SUPPORT_SAVE_TARGETS 0

namespace XClip {

enum CommonAtom {
  ATOM,
  INCR,
  TARGETS,
  CLIPBOARD,
#ifdef CLIP_SUPPORT_SAVE_TARGETS
  ATOM_PAIR,
  SAVE_TARGETS,
  MULTIPLE,
  CLIPBOARD_MANAGER,
#endif
};

const char* kCommonAtomNames[] = {
  "ATOM",
  "INCR",
  "TARGETS",
  "CLIPBOARD",
#ifdef CLIP_SUPPORT_SAVE_TARGETS
  "ATOM_PAIR",
  "SAVE_TARGETS",
  "MULTIPLE",
  "CLIPBOARD_MANAGER",
#endif
};

class Manager {
public:
  typedef std::shared_ptr<std::vector<uint8_t>> buffer_ptr;
  typedef std::vector<xcb_atom_t> atoms;
  typedef std::function<bool()> notify_callback;

  Manager()
    : m_lock(m_mutex, std::defer_lock)
    , m_connection(xcb_connect(nullptr, nullptr))
    , m_window(0) {
    if (!m_connection)
      return;

    const xcb_setup_t* setup = xcb_get_setup(m_connection);
    if (!setup)
      return;

    xcb_screen_t* screen = xcb_setup_roots_iterator(setup).data;
    if (!screen)
      return;

    uint32_t event_mask =
      // Just in case that some program reports SelectionNotify events
      // with XCB_EVENT_MASK_PROPERTY_CHANGE mask.
      XCB_EVENT_MASK_PROPERTY_CHANGE |
      // To receive DestroyNotify event and stop the message loop.
      XCB_EVENT_MASK_STRUCTURE_NOTIFY;

    m_window = xcb_generate_id(m_connection);
    xcb_create_window(m_connection, 0,
                      m_window,
                      screen->root,
                      0, 0, 1, 1, 0,
                      XCB_WINDOW_CLASS_INPUT_OUTPUT,
                      screen->root_visual,
                      XCB_CW_EVENT_MASK,
                      &event_mask);

    m_thread = std::thread(
      [this]{
        process_x11_events();
      });
  }

  ~Manager() {
    if (m_window) {
      xcb_destroy_window(m_connection, m_window);
      xcb_flush(m_connection);
    }

    if (m_thread.joinable())
      m_thread.join();

    if (m_connection)
      xcb_disconnect(m_connection);
  }

  bool try_lock() {
    bool res = m_lock.try_lock();
    if (!res) {
      // TODO make this configurable (the same for Windows retries)
      for (int i=0; i<5 && !res; ++i) {
        res = m_lock.try_lock();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
    }
    return res;
  }

  void unlock() {
    m_lock.unlock();
  }

  // Clear our data
  void clear_data() {
	for (auto& [atom,ptr] : m_data){
		if (ptr)
			std::fill(ptr->begin(),ptr->end(),0);
	}
    m_data.clear();
  }

  bool set_data(const char* buf, size_t len) {
    if (!set_x11_selection_owner())
      return false;

    const atoms atoms = get_text_format_atoms();
    if (atoms.empty())
      return false;

    buffer_ptr shared_data_buf = std::make_shared<std::vector<uint8_t>>(len);
    std::copy(buf,
              buf+len,
              shared_data_buf->begin());
    for (xcb_atom_t atom : atoms)
      m_data[atom] = shared_data_buf;

    return true;
  }

private:

  void process_x11_events() {
    bool stop = false;
    xcb_generic_event_t* event;
    while (!stop && (event = xcb_wait_for_event(m_connection))) {
      int type = (event->response_type & ~0x80);

      switch (type) {
        case XCB_DESTROY_NOTIFY:
          // To stop the message loop we can just destroy the window
          stop = true;
          break;

        // Someone else has new content in the clipboard, so is
        // notifying us that we should delete our data now.
        case XCB_SELECTION_CLEAR:
          handle_selection_clear_event(
            (xcb_selection_clear_event_t*)event);
          break;

          // Someone is requesting the clipboard content from us.
        case XCB_SELECTION_REQUEST:
          handle_selection_request_event(
            (xcb_selection_request_event_t*)event);
          break;
      }

      free(event);
    }
  }

  void handle_selection_clear_event(xcb_selection_clear_event_t* event) {
    if (event->selection == get_atom(CLIPBOARD)) {
      std::lock_guard<std::mutex> lock(m_mutex);
      clear_data(); // Clear our clipboard data
    }
  }

  void handle_selection_request_event(xcb_selection_request_event_t* event) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (event->target == get_atom(TARGETS)) {
      atoms targets;
      targets.push_back(get_atom(TARGETS));
#ifdef CLIP_SUPPORT_SAVE_TARGETS
      targets.push_back(get_atom(SAVE_TARGETS));
      targets.push_back(get_atom(MULTIPLE));
#endif
      for (const auto& it : m_data)
        targets.push_back(it.first);

      // Set the "property" of "requestor" with the clipboard
      // formats ("targets", atoms) that we provide.
      xcb_change_property(
        m_connection,
        XCB_PROP_MODE_REPLACE,
        event->requestor,
        event->property,
        get_atom(ATOM),
        8*sizeof(xcb_atom_t),
        targets.size(),
        &targets[0]);
    }
#ifdef CLIP_SUPPORT_SAVE_TARGETS
    else if (event->target == get_atom(SAVE_TARGETS)) {
      // Do nothing
    }
    else if (event->target == get_atom(MULTIPLE)) {
      xcb_get_property_reply_t* reply =
        get_and_delete_property(event->requestor,
                                event->property,
                                get_atom(ATOM_PAIR),
                                false);
      if (reply) {
        for (xcb_atom_t
               *ptr=(xcb_atom_t*)xcb_get_property_value(reply),
               *end=ptr + (xcb_get_property_value_length(reply)/sizeof(xcb_atom_t));
             ptr<end; ) {
          xcb_atom_t target = *ptr++;
          xcb_atom_t property = *ptr++;

          if (!set_requestor_property_with_clipboard_content(
                event->requestor,
                property,
                target)) {
            xcb_change_property(
              m_connection,
              XCB_PROP_MODE_REPLACE,
              event->requestor,
              event->property,
              XCB_ATOM_NONE, 0, 0, nullptr);
          }
        }

        free(reply);
      }
    }
#endif // CLIP_SUPPORT_SAVE_TARGETS
    else {
      if (!set_requestor_property_with_clipboard_content(
            event->requestor,
            event->property,
            event->target)) {
        return;
      }
    }

    // Notify the "requestor" that we've already updated the property.
    xcb_selection_notify_event_t notify;
    notify.response_type = XCB_SELECTION_NOTIFY;
    notify.pad0          = 0;
    notify.sequence      = 0;
    notify.time          = event->time;
    notify.requestor     = event->requestor;
    notify.selection     = event->selection;
    notify.target        = event->target;
    notify.property      = event->property;

    xcb_send_event(m_connection, false,
                   event->requestor,
                   XCB_EVENT_MASK_NO_EVENT, // SelectionNotify events go without mask
                   (const char*)&notify);

    xcb_flush(m_connection);
  }

  bool set_requestor_property_with_clipboard_content(const xcb_atom_t requestor,
                                                     const xcb_atom_t property,
                                                     const xcb_atom_t target) {
    auto it = m_data.find(target);
    if (it == m_data.end()) {
      // Nothing to do (unsupported target)
      return false;
    }

	if (!it->second)
		return false;

    // Set the "property" of "requestor" with the
    // clipboard content in the requested format ("target").
    xcb_change_property(
      m_connection,
      XCB_PROP_MODE_REPLACE,
      requestor,
      property,
      target,
      8,
      it->second->size(),
      &(*it->second)[0]);
    return true;
  }

  xcb_get_property_reply_t* get_and_delete_property(xcb_window_t window,
                                                    xcb_atom_t property,
                                                    xcb_atom_t atom,
                                                    bool delete_prop = true) {
    xcb_get_property_cookie_t cookie =
      xcb_get_property(m_connection,
                       delete_prop,
                       window,
                       property,
                       atom,
                       0, 0x1fffffff); // 0x1fffffff = INT32_MAX / 4

    xcb_generic_error_t* err = nullptr;
    xcb_get_property_reply_t* reply =
      xcb_get_property_reply(m_connection, cookie, &err);
    if (err) {
      // TODO report error
      free(err);
    }
    return reply;
  }

  atoms get_atoms(const char** names,
                  const int n) const {
    atoms result(n, 0);
    std::vector<xcb_intern_atom_cookie_t> cookies(n);

    for (int i=0; i<n; ++i) {
      auto it = m_atoms.find(names[i]);
      if (it != m_atoms.end())
        result[i] = it->second;
      else
        cookies[i] = xcb_intern_atom(
          m_connection, 0,
          std::strlen(names[i]), names[i]);
    }

    for (int i=0; i<n; ++i) {
      if (result[i] == 0) {
        xcb_intern_atom_reply_t* reply =
          xcb_intern_atom_reply(m_connection,
                                cookies[i],
                                nullptr);
        if (reply) {
          result[i] = m_atoms[names[i]] = reply->atom;
          free(reply);
        }
      }
    }

    return result;
  }

  xcb_atom_t get_atom(const char* name) const {
    auto it = m_atoms.find(name);
    if (it != m_atoms.end())
      return it->second;

    xcb_atom_t result = 0;
    xcb_intern_atom_cookie_t cookie =
      xcb_intern_atom(m_connection, 0,
                      std::strlen(name), name);

    xcb_intern_atom_reply_t* reply =
      xcb_intern_atom_reply(m_connection,
                            cookie,
                            nullptr);
    if (reply) {
      result = m_atoms[name] = reply->atom;
      free(reply);
    }
    return result;
  }

  xcb_atom_t get_atom(CommonAtom i) const {
    if (m_common_atoms.empty()) {
      m_common_atoms =
        get_atoms(kCommonAtomNames,
                  sizeof(kCommonAtomNames) / sizeof(kCommonAtomNames[0]));
    }
    return m_common_atoms[i];
  }

  const atoms& get_text_format_atoms() const {
    if (m_text_atoms.empty()) {
      const char* names[] = {
        // Prefer utf-8 formats first
        "UTF8_STRING",
        "text/plain;charset=utf-8",
        "text/plain;charset=UTF-8",
        "GTK_TEXT_BUFFER_CONTENTS", // Required for gedit (and maybe gtk+ apps)
        // ANSI C strings?
        "STRING",
        "TEXT",
        "text/plain",
      };
      m_text_atoms = get_atoms(names, sizeof(names) / sizeof(names[0]));
    }
    return m_text_atoms;
  }

  bool set_x11_selection_owner() const {
    xcb_void_cookie_t cookie =
      xcb_set_selection_owner_checked(m_connection,
                                      m_window,
                                      get_atom(CLIPBOARD),
                                      XCB_CURRENT_TIME);
    xcb_generic_error_t* err =
      xcb_request_check(m_connection,
                        cookie);
    if (err) {
      free(err);
      return false;
    }
    return true;
  }

  xcb_window_t get_x11_selection_owner() const {
    xcb_window_t result = 0;
    xcb_get_selection_owner_cookie_t cookie =
      xcb_get_selection_owner(m_connection,
                              get_atom(CLIPBOARD));

    xcb_get_selection_owner_reply_t* reply =
      xcb_get_selection_owner_reply(m_connection, cookie, nullptr);
    if (reply) {
      result = reply->owner;
      free(reply);
    }
    return result;
  }

  // Access to the whole Manager
  std::mutex m_mutex;

  // Lock used in the main thread using the Manager (i.e. by lock::impl)
  mutable std::unique_lock<std::mutex> m_lock;

  // Connection to X11 server
  xcb_connection_t* m_connection;

  // Temporal background window used to own the clipboard and process
  // all events related about the clipboard in a background thread
  xcb_window_t m_window;

  // Thread used to run a background message loop to wait X11 events
  // about clipboard. The X11 selection owner will be a hidden window
  // created by us just for the clipboard purpose/communication.
  std::thread m_thread;

  // Cache of known atoms
  mutable std::map<std::string, xcb_atom_t> m_atoms;

  // Cache of common used atoms by us
  mutable atoms m_common_atoms;

  // Cache of atoms related to text
  mutable atoms m_text_atoms;

  // Actual clipboard data generated by us (when we "copy" content in
  // the clipboard, it means that we own the X11 "CLIPBOARD"
  // selection, and in case of SelectionRequest events, we've to
  // return the data stored in this "m_data" field)
  mutable std::map<xcb_atom_t, buffer_ptr> m_data;
};

Manager* manager = nullptr;

void delete_manager_atexit() {
  if (manager) {
	manager->clear_data();
    delete manager;
    manager = nullptr;
  }
}

Manager* get_manager() {
  if (!manager) {
    manager = new Manager;
    std::atexit(delete_manager_atexit);
  }
  return manager;
}

} // anonymous namespace

