/**
 *  VirtualKEY Device Handler
 *
 *  Copyright 2017 VirtualKEY
 *
 *  Version is v3.8.6
 */
metadata {
	definition (name: "VirtualKEY Device Handler", namespace: "com.virtualkey.smartthings.devicehandler", author: "VirtualKEY") {
		capability "Actuator"
		capability "Lock"
		capability "Polling"
		capability "Refresh"
		capability "Sensor"
		capability "Lock Codes"
		capability "Battery"
		capability "Health Check"

		command "unlockwtimeout"
        command "displaystatedb"
        command "getBatteryLevelFromLock"
        
        command "enableOneTouchLockingForYale"
        command "disableOneTouchLockingForYale"
        command "getConfiguration"
        
        command "enableLockAndLeaveForSchlage"
        command "disableLockAndLeaveForSchalge"
        
        command "setIncorrectEntryLimitToThree"
        
        command "setYearDayScheduleAPI", ["number", "number", "number", "number", "number", "number", "number", "number", "number", "number", "number", "number"]
		command "getYearDaySchedule", ["number", "number"]
        
		command "getScheduleEntryTypeSupported"
        command "setTimeParameters"
        command "getTimeParameters"
		command "setScheduleTimeOffset"
        command "getScheduleTimeOffset"
        command "refreshAllAccessCodes"
        command "deleteAllCodes"
        command "setConfigParameters",["number", "number"]
		command "getMSRFromLock"
		command "getVersionFromLock"
		command "getMaxSlotsFromLock"
        command "enableAutoLockForSchlage"
        command "disableAutoLockForSchlage"
        command "getAutoLockForSchlage"
        command "enableAutoLockFor60Seconds"
		command "enableAutoLockFor180Seconds"
        command "enableAutoLockFor120Seconds"
        command "enableAutoLockFor30Seconds"
        command "getAutoLockForYale"
        command "disableAutoLockOnYale"
        command "lockViaApi"
        command "unlockViaApi"
		command "disablePrivacyButtonOnYale"
		command "enablePrivacyButtonOnYale"
		command "setOperatingModeToNormalOnYale"
		command "setOperatingModeToVacationOnYale"
		command "setOperatingModeToPrivacyOnYale"

        command "clearYearDaySchedule", ["number", "number"]
        command "clearAllYearDaySchedule", ["number"]
        
		fingerprint deviceId: "0x4003", inClusters: "0x98"
		fingerprint deviceId: "0x4004", inClusters: "0x98"
		fingerprint mfr:"0129", prod:"0002", model:"0000", deviceJoinName: "Yale Key Free Touchscreen Deadbolt"
	}

	simulator {
		status "locked": "command: 9881, payload: 00 62 03 FF 00 00 FE FE"
		status "unlocked": "command: 9881, payload: 00 62 03 00 00 00 FE FE"

		reply "9881006201FF,delay 4200,9881006202": "command: 9881, payload: 00 62 03 FF 00 00 FE FE"
		reply "988100620100,delay 4200,9881006202": "command: 9881, payload: 00 62 03 00 00 00 FE FE"
	}

	tiles(scale: 2) {
		multiAttributeTile(name:"toggle", type: "generic", width: 6, height: 4){
			tileAttribute ("device.lock", key: "PRIMARY_CONTROL") {
				attributeState "locked", label:'locked', action:"lock.unlock", icon:"st.locks.lock.locked", backgroundColor:"#79b821", nextState:"unlocking"
				attributeState "unlocked", label:'unlocked', action:"lock.lock", icon:"st.locks.lock.unlocked", backgroundColor:"#ffffff", nextState:"locking"
				attributeState "unknown", label:"unknown", action:"lock.lock", icon:"st.locks.lock.unknown", backgroundColor:"#ffffff", nextState:"locking"
				attributeState "locking", label:'locking', icon:"st.locks.lock.locked", backgroundColor:"#79b821"
				attributeState "unlocking", label:'unlocking', icon:"st.locks.lock.unlocked", backgroundColor:"#ffffff"
			}
		}
		standardTile("lock", "device.lock", inactiveLabel: false, decoration: "flat", width: 2, height: 2) {
			state "default", label:'lock', action:"lock.lock", icon:"st.locks.lock.locked", nextState:"locking"
		}
		standardTile("unlock", "device.lock", inactiveLabel: false, decoration: "flat", width: 2, height: 2) {
			state "default", label:'unlock', action:"lock.unlock", icon:"st.locks.lock.unlocked", nextState:"unlocking"
		}
		valueTile("battery", "device.battery", inactiveLabel: false, decoration: "flat", width: 2, height: 2) {
			state "battery", label:'${currentValue}% battery', unit:""
		}
		standardTile("refresh", "device.lock", inactiveLabel: false, decoration: "flat", width: 2, height: 2) {
			state "default", label:'', action:"refresh.refresh", icon:"st.secondary.refresh"
		}

		main "toggle"
		details(["toggle", "lock", "unlock", "battery", "refresh"])
	}
}

import physicalgraph.zwave.commands.doorlockv1.*
import physicalgraph.zwave.commands.usercodev1.*
import static java.util.Calendar.*

/**
 * Responsible for listing all the user codes
 */
def refreshAllAccessCodes(){
	log.debug "Inside refreshAllAccessCodes"
	def commands = [];
	
	for (int i=1;i<=state.codes;i++){
		commands << zwave.userCodeV1.userCodeGet(userIdentifier: i);
	}
    
	delayBetween(commands.collect{ secure(it) }, 7000);
}

/**
 * Responsible for enabling Auto Lock for Schlage locks
 */
def enableAutoLockForSchlage() {
	log.debug "Inside enableAutoLockForSchlage"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 0x0F, size: 1, configurationValue: [ 0xFF ]),
		zwave.configurationV2.configurationGet(parameterNumber: 0x0F) ], 2000)

}
/**
 * Responsible for disabling Auto Lock for Schlage locks
 */
def disableAutoLockForSchlage() {
	log.debug "Inside disableAutoLockForSchlage"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 0x0F, size: 1, configurationValue: [ 0x00 ]),
		zwave.configurationV2.configurationGet(parameterNumber: 0x0F) ], 2000)

}

/**
 * Responsible for getting Auto Lock Status for Schlage
 */
def getAutoLockForSchlage() {
	log.debug "Inside getAutoLockForSchlage"
	secure(zwave.configurationV2.configurationGet(parameterNumber: 0x0F))

}

/**
 * Responsible for enabling Auto Lock for Yale locks and set it to 60 seconds
 */
def getAutoLockForYale() {
	log.debug "Inside getAutoLockForYale"
	secureSequence([ zwave.configurationV2.configurationGet(parameterNumber: 3),
		zwave.configurationV2.configurationGet(parameterNumber: 2) ], 2000)
}


/**
 * Responsible for enabling Auto Lock for Yale locks and set it to 60 seconds
 */
def enableAutoLockFor60Seconds() {
	log.debug "Inside enableAutoLockFor60Seconds"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 2, size: 1, configurationValue: [ 0xFF ]),
		zwave.configurationV2.configurationSet(parameterNumber: 3, size: 1, configurationValue: [ 0x3C ]),
		zwave.configurationV2.configurationGet(parameterNumber: 3),
		zwave.configurationV2.configurationGet(parameterNumber: 2) ], 2000)
}

/**
 * Responsible for enabling Auto Lock for Yale locks and set it to 120 seconds
 */
def enableAutoLockFor120Seconds() {
	log.debug "Inside enableAutoLockFor120Seconds"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 2, size: 1, configurationValue: [ 0xFF ]),
		zwave.configurationV2.configurationSet(parameterNumber: 3, size: 1, configurationValue: [ 0x78 ]),
		zwave.configurationV2.configurationGet(parameterNumber: 3),
		zwave.configurationV2.configurationGet(parameterNumber: 2) ], 2000)
}


/**
 * Responsible for enabling Auto Lock for Yale locks and set it to 180 seconds
 */
def enableAutoLockFor180Seconds() {
	log.debug "Inside enableAutoLockFor180Seconds"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 2, size: 1, configurationValue: [ 0xFF ]),
		zwave.configurationV2.configurationSet(parameterNumber: 3, size: 1, configurationValue: [ 0xB4 ]),
		zwave.configurationV2.configurationGet(parameterNumber: 3),
		zwave.configurationV2.configurationGet(parameterNumber: 2) ], 2000)
}


/**
 * Responsible for enabling Auto Lock for Yale locks and set it to 60 seconds
 */
def enableAutoLockFor30Seconds() {
	log.debug "Inside enableAutoLockFor30Seconds"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 2, size: 1, configurationValue: [ 0xFF ]),
		zwave.configurationV2.configurationSet(parameterNumber: 3, size: 1, configurationValue: [ 0x1E ]),
		zwave.configurationV2.configurationGet(parameterNumber: 3),
		zwave.configurationV2.configurationGet(parameterNumber: 2) ], 2000)
}

/**
 * Responsible for disabling Auto Lock for Yale locks
 */
def disableAutoLockOnYale() {
	log.debug "Inside disableAutoLockOnYale"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 2, size: 1, configurationValue: [ 0x00 ]),
		zwave.configurationV2.configurationGet(parameterNumber: 2) ], 2000)
}


/**
 * Responsible for deleting all the user codes on the lock
 */
def deleteAllCodes(){
    log.debug "Inside deleteAllCodes"

	def commands = [];
    commands << zwave.userCodeV1.userCodeSet(userIdentifier:0, userIdStatus:0);
	
	delayBetween(commands.collect{ secure(it) }, 7000)
}

/**
 * Responsible for setting the Incorrect entry limit to 3
 */
def setIncorrectEntryLimitToThree() {
	log.debug "Inside setIncorrectEntryLimitToThree"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 4, size: 1, configurationValue: [ 0x03 ]),
		zwave.configurationV2.configurationGet(parameterNumber: 4) ], 2000)
}

/**
 * Responsible for disabling One touch locking for Yale locks
 */
def disableOneTouchLockingForYale() {
	log.debug "Inside disableOneTouchLockingForYale"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 11, size: 1, configurationValue: [ 0x00 ]),
		zwave.configurationV2.configurationGet(parameterNumber: 11) ], 2000)
}

/**
 * Responsible for enabling One touch locking for Yale locks
 */
def enableOneTouchLockingForYale() {
	log.debug "Inside enableOneTouchLockingForYale"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 11, size: 1, configurationValue: [ 0xFF ]),
		zwave.configurationV2.configurationGet(parameterNumber: 11) ], 2000)
}

/**
 * Responsible for setting a configuration parameter
 *
 * @params: Configuration variable which needs to be set, configuration value
 */
def setConfigParameters(parameterNumber, configurationValue) {
	log.debug "Inside setConfigParameters"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: parameterNumber, size: 1, configurationValue: [ configurationValue ]),
		zwave.configurationV2.configurationGet(parameterNumber: parameterNumber) ], 2000)
}

/**
 * Responsible for enabling Lock and Leave for Schlage locks
 */
def enableLockAndLeaveForSchlage() {
	log.debug "Inside enableLockAndLeaveForSchlage"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 5, size: 1, configurationValue: [ 0xFF ]),
		zwave.configurationV2.configurationGet(parameterNumber: 5) ], 2000)
}

/**
 * Responsible for disabling Lock and Leave for Schlage locks
 */
def disableLockAndLeaveForSchalge() {
	log.debug "Inside disableLockAndLeaveForSchalge"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 5, size: 1, configurationValue: [ 0x00 ]),
		zwave.configurationV2.configurationGet(parameterNumber: 5) ], 2000)
}

/**
 * Responsible for getting all the configurations of the device
 */
def getConfiguration() {
	log.debug "Inside getConfiguration"
	secureSequence([ zwave.configurationV2.configurationGet(parameterNumber: 1),
            zwave.configurationV2.configurationGet(parameterNumber: 2),
            zwave.configurationV2.configurationGet(parameterNumber: 3),
            zwave.configurationV2.configurationGet(parameterNumber: 4),
            zwave.configurationV2.configurationGet(parameterNumber: 5),
            zwave.configurationV2.configurationGet(parameterNumber: 6),
            zwave.configurationV2.configurationGet(parameterNumber: 7),
            zwave.configurationV2.configurationGet(parameterNumber: 8),
            zwave.configurationV2.configurationGet(parameterNumber: 9),
            zwave.configurationV2.configurationGet(parameterNumber: 10),
            zwave.configurationV2.configurationGet(parameterNumber: 11),
            zwave.configurationV2.configurationGet(parameterNumber: 12),
            zwave.configurationV2.configurationGet(parameterNumber: 13)], 2000)
}

def updated() {
	// Device-Watch simply pings if no device events received for 32min(checkInterval)
	sendEvent(name: "checkInterval", value: 2 * 15 * 60 + 2 * 60, displayed: false, data: [protocol: "zwave", hubHardwareId: device.hub.hardwareID])
	try {
		if (!state.init) {
			state.init = true
			response(secureSequence([zwave.doorLockV1.doorLockOperationGet(), zwave.batteryV1.batteryGet()]))
		}
	} catch (e) {
		log.warn "updated() threw $e"
	}
}

def parse(String description) {
	def result = null
	if (description.startsWith("Err 106")) {
		if (state.sec) {
			result = createEvent(descriptionText:description, displayed:false)
		} else {
			result = createEvent(
				descriptionText: "This lock failed to complete the network security key exchange. If you are unable to control it via SmartThings, you must remove it from your network and add it again.",
				eventType: "ALERT",
				name: "secureInclusion",
				value: "failed",
				displayed: true,
			)
		}
	} else if (description == "updated") {
		return null
	} else {
		def cmd = zwave.parse(description, [ 0x98: 1, 0x72: 2, 0x85: 2, 0x86: 1, 0x4E: 3 ])
		if (cmd) {
			result = zwaveEvent(cmd)
		}
	}
	log.debug "\"$description\" parsed to ${result.inspect()}"
	return result
}

def zwaveEvent(physicalgraph.zwave.commands.securityv1.SecurityMessageEncapsulation cmd) {
	def encapsulatedCommand = cmd.encapsulatedCommand([0x62: 1, 0x71: 2, 0x80: 1, 0x85: 2, 0x63: 1, 0x98: 1, 0x86: 1])
	// log.debug "encapsulated: $encapsulatedCommand"
	if (encapsulatedCommand) {
		zwaveEvent(encapsulatedCommand)
	}
}

def zwaveEvent(physicalgraph.zwave.commands.securityv1.NetworkKeyVerify cmd) {
	createEvent(name:"secureInclusion", value:"success", descriptionText:"Secure inclusion was successful")
}

def zwaveEvent(physicalgraph.zwave.commands.securityv1.SecurityCommandsSupportedReport cmd) {
	state.sec = cmd.commandClassSupport.collect { String.format("%02X ", it) }.join()
	if (cmd.commandClassControl) {
		state.secCon = cmd.commandClassControl.collect { String.format("%02X ", it) }.join()
	}
	log.debug "Security command classes: $state.sec"
	createEvent(name:"secureInclusion", value:"success", descriptionText:"Lock is securely included")
}

/**
 * Responsible for parsing DoorLockOperationReport command
 *
 * @param cmd: The DoorLockOperationReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */

// DoorLockOperationReport is called when trying to read the lock state or when the lock is locked/unlocked from the DTH or the smart app
def zwaveEvent(DoorLockOperationReport cmd) {
	def result = []
	def map = [ name: "lock" ]
	if (cmd.doorLockMode == 0xFF) {
		map.value = "locked"
        map.data = groovy.json.JsonOutput.toJson([eventTypeId: "100", status: "locked",slotnumber:""])
	} else if (cmd.doorLockMode >= 0x40) {
		map.value = "unknown"
        map.data = groovy.json.JsonOutput.toJson([eventTypeId: "101",status: "DoorLockOperationReport unknown",slotnumber:""])
	} else if (cmd.doorLockMode & 1) {
		map.value = "unlocked with timeout"
        map.data = groovy.json.JsonOutput.toJson([eventTypeId: "102",status: "DoorLockOperationReport unlocked with timeout",slotnumber:""])
	} else {
		map.value = "unlocked"
        map.data = groovy.json.JsonOutput.toJson([eventTypeId: "103",status: "unlocked",slotnumber:""])
		if (state.assoc != zwaveHubNodeId) {
			log.debug "setting association"
			result << response(secure(zwave.associationV1.associationSet(groupingIdentifier:1, nodeId:zwaveHubNodeId)))
			result << response(zwave.associationV1.associationSet(groupingIdentifier:2, nodeId:zwaveHubNodeId))
			result << response(secure(zwave.associationV1.associationGet(groupingIdentifier:1)))
		}
	}
    log.debug "This is a DoorLockOperationReport";
	return result ? [createEvent(map), *result] : createEvent(map)
}

/**
 * Responsible for parsing AlarmReport command
 *
 * @param cmd: The AlarmReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(physicalgraph.zwave.commands.alarmv2.AlarmReport cmd) {
	log.debug "Inside zwaveEvent-AlarmReport, parsing AlarmReport command = $cmd"
	
	log.debug "alarmLevel= $cmd.alarmLevel";
	log.debug "alarmType= $cmd.alarmType";
	log.debug "numberOfEventParameters= $cmd.numberOfEventParameters";
	log.debug "zwaveAlarmEvent= $cmd.zwaveAlarmEvent";
	log.debug "zwaveAlarmStatus= $cmd.zwaveAlarmStatus";
	log.debug "zwaveAlarmType= $cmd.zwaveAlarmType";
	log.debug "eventParameter= ${cmd.eventParameter}";
	
    def result = []
	if (cmd.zwaveAlarmType == 6) { // Access alarm report
		result = handleAccessAlarmReport(cmd)
	} else if (cmd.zwaveAlarmType == 7) { // Burglar alarm report
		result = handleBurglarAlarmReport(cmd)
	} else if(cmd.zwaveAlarmType == 8) { // Battery alarm report
		result = handleBatteryAlarmReport(cmd)
	} else { // default handler for all other alarms and older devices
		result = handleAlarmReportUsingAlarmType(cmd)
	}

	result = result ?: null
	log.debug "End of zwaveEvent-AlarmReport; returning with result = $result"
	result
}
	
/**
 * Responsible for handling Access AlarmReport command
 *
 * @param cmd: The AlarmReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
private def handleAccessAlarmReport(cmd) {
	log.debug "Inside handleAccessAlarmReport"
	
	def result = []
	def map = null
	
	if (1 <= cmd.zwaveAlarmEvent && cmd.zwaveAlarmEvent < 10) {
		map = [ name: "lock", value: (cmd.zwaveAlarmEvent & 1) ? "locked" : "unlocked", data: groovy.json.JsonOutput.toJson([eventTypeId: "104", status: (cmd.zwaveAlarmEvent & 1) ? "locked" : "unlocked"])]
	}
	switch(cmd.zwaveAlarmEvent) {
		case 1: // Manually Locked
			map.descriptionText = "$device.displayName was manually locked"
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "105", status: (cmd.zwaveAlarmEvent & 1) ? "locked" : "unlocked",slotnumber: "manual"])
			map.isStateChange = true
			break
		case 2: // Manually Unlocked
			map.descriptionText = "$device.displayName was manually unlocked"
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "106", status: (cmd.zwaveAlarmEvent & 1) ? "locked" : "unlocked",slotnumber: "manual"])
			map.isStateChange = true
			break
		case 5: // Locked by Keypad
			if (cmd.eventParameter) {
                log.debug "Finding the correct slot number where the event occurred and generating the appropriate event"
            	if(cmd.numberOfEventParameters == 1) {
                    map.descriptionText = "$device.displayName was locked with code ${cmd.eventParameter[0]}"
	                map.data = groovy.json.JsonOutput.toJson([eventTypeId: "107", status: (cmd.zwaveAlarmEvent & 1) ? "locked" : "unlocked",slotnumber: cmd.eventParameter[0]])
				} else if(cmd.numberOfEventParameters >= 3) { // Yale doesn't follow Z-Wave specs and eventParameter contains user slot in 3rd byte e.g.: user 2 reported as [99, 3, 2, 1]
                    map.descriptionText = "$device.displayName was locked with code ${cmd.eventParameter[2]}"
	                map.data = groovy.json.JsonOutput.toJson([eventTypeId: "107", status: (cmd.zwaveAlarmEvent & 1) ? "locked" : "unlocked",slotnumber: cmd.eventParameter[2]])
				} else {
                    map.descriptionText = "$device.displayName was locked with code ${cmd.alarmLevel}"
	                map.data = groovy.json.JsonOutput.toJson([eventTypeId: "107", status: (cmd.zwaveAlarmEvent & 1) ? "locked" : "unlocked",slotnumber: cmd.alarmLevel])
				}
				map.isStateChange = true
			}
			break
		case 6: // Unlocked by Keypad
			if (cmd.eventParameter) {
                log.debug "Finding the correct slot number where the event occurred and generating the appropriate event"
            	if(cmd.numberOfEventParameters == 1) {
					map.descriptionText = "$device.displayName was unlocked with code ${cmd.eventParameter[0]}"
                	map.data = groovy.json.JsonOutput.toJson([eventTypeId: "108", status: (cmd.zwaveAlarmEvent & 1) ? "locked" : "unlocked",slotnumber: cmd.eventParameter[0]])
				} else if(cmd.numberOfEventParameters >= 3) { // Yale doesn't follow Z-Wave specs and eventParameter contains user slot in 3rd byte e.g.: user 2 reported as [99, 3, 2, 1]
					map.descriptionText = "$device.displayName was unlocked with code ${cmd.eventParameter[2]}"
                	map.data = groovy.json.JsonOutput.toJson([eventTypeId: "108", status: (cmd.zwaveAlarmEvent & 1) ? "locked" : "unlocked",slotnumber: cmd.eventParameter[2]])
				} else {
					map.descriptionText = "$device.displayName was unlocked with code ${cmd.alarmLevel}"
                	map.data = groovy.json.JsonOutput.toJson([eventTypeId: "108", status: (cmd.zwaveAlarmEvent & 1) ? "locked" : "unlocked",slotnumber: cmd.alarmLevel])
				}
                map.value = "unlocked"
				map.isStateChange = true
            }
			break
		case 9: // Auto Lock
			map.descriptionText = "$device.displayName was autolocked"
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "109", status: (cmd.zwaveAlarmEvent & 1) ? "locked" : "unlocked",slotnumber: "auto"])
			map.isStateChange = true
			break
		case 7:
		case 8:
		case 0xA: // Unknown state
			map = [ name: "lock", value: "unknown", descriptionText: "$device.displayName was not locked fully" ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "110", status: "not locked fully",slotnumber: ""])
			map.isStateChange = true
			break
		case 0xB: // Lock Jammed
			map = [ name: "lock", value: "unknown", descriptionText: "$device.displayName is jammed" ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "111", status: "lock is jammed",slotnumber: ""])
			map.isStateChange = true
			break
		case 0xC: // All codes deleted
			map = [ name: "codeChanged", value: "all", descriptionText: "$device.displayName: all user codes deleted", isStateChange: true ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "112", status: "all user codes deleted",slotnumber: ""])
			map.isStateChange = true
			break
		case 0xD: // User Code deleted
			if (cmd.eventParameter) {
				map = [ name: "codeReport", value: cmd.eventParameter[0], data: [ code: "" ], isStateChange: true ]
				map.descriptionText = "$device.displayName code ${map.value} was deleted"
				map.isStateChange = (state["code$map.value"] != "")
				state["code$map.value"] = ""
				map.data = groovy.json.JsonOutput.toJson([eventTypeId: "113", status: "code was deleted",slotnumber: cmd.eventParameter[0]])
			} else {
				map = [ name: "codeChanged", descriptionText: "$device.displayName: user code deleted", isStateChange: true ]
				map.data = groovy.json.JsonOutput.toJson([eventTypeId: "114", status: "user code deleted",slotnumber: ""])
			}
			break
		case 0xE: // User Code deleted
			map = [ name: "codeChanged", value: cmd.alarmLevel,  descriptionText: "$device.displayName: user code deleted", isStateChange: true ]
			if (cmd.eventParameter) {
				map.value = cmd.eventParameter[0]
				map.data = groovy.json.JsonOutput.toJson([eventTypeId: "114", status: "user code deleted",slotnumber: cmd.eventParameter[0]])
				result << response(requestCode(cmd.eventParameter[0]))
			}
			break
		case 0xF: //  Code creation failed, duplicate code
			map = [ name: "codeChanged", descriptionText: "$device.displayName: user code not added, duplicate", isStateChange: true ]
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "116", status: "user code not added, duplicate",slotnumber:cmd.alarmLevel])
			break
		case 0x10: // Keypad disabled
			map = [ name: "tamper", value: "detected", descriptionText: "$device.displayName: keypad temporarily disabled", displayed: true, isStateChange: true ]
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "117", status: "keypad temporarily disabled",slotnumber:""])
			break
		case 0x11: // keypad busy
			map = [ descriptionText: "$device.displayName: keypad is busy", isStateChange: true ]
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "118", status: "keypad is busy",slotnumber:""])
			break
		case 0x12: // Master code changed ?
			map = [ name: "codeChanged", descriptionText: "$device.displayName: program code changed", isStateChange: true ]
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "119", status: " program code changed",slotnumber:""])
			break
		case 0x13: // Maximum incorrect attempts
			map = [ name: "tamper", value: "detected", descriptionText: "$device.displayName: code entry attempt limit exceeded", displayed: true, isStateChange: true ]
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "120", status: "code entry attempt limit exceeded",slotnumber:""])
			break
		default:
			// delegating it to handleAlarmReportUsingAlarmType
			return handleAlarmReportUsingAlarmType(cmd)
	}
	
	
	result << createEvent(map)
    log.trace "End of handleAccessAlarmReport with result $result"
    result
}


/**
 * Responsible for handling Burglar AlarmReport command
 *
 * @param cmd: The AlarmReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
private def handleBurglarAlarmReport(cmd) {
	log.trace "Inside handleBurglarAlarmReport"
	def result = []

	def map = [ name: "tamper", value: "detected", displayed: true , isStateChange: true]
	switch (cmd.zwaveAlarmEvent) {
		case 0:
			map.value = "clear"
			map.descriptionText = "$device.displayName: tamper alert cleared"
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "122", status: "tamper alert cleared",slotnumber:""])
			break
		case 1:
		case 2:
			map.descriptionText = "$device.displayName: intrusion attempt detected"
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "123", status: "intrusion attempt detected",slotnumber:""])
			break
		case 3:
			map.descriptionText = "$device.displayName: covering removed"
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "124", status: "covering removed",slotnumber:""])
			break
		case 4:
			map.descriptionText = "$device.displayName: invalid code"
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "125", status: "invalid code",slotnumber:""])
			break
		default:
			// delegating it to handleAlarmReportUsingAlarmType
			return handleAlarmReportUsingAlarmType(cmd)
	}
	
	log.trace "End of handleBurglarAlarmReport"
	result << createEvent(map)
    result
}

/**
 * Responsible for handling Battery AlarmReport command
 *
 * @param cmd: The AlarmReport command to be parsed
 *
 * @return The event(s) to be sent out
 */
private def handleBatteryAlarmReport(cmd) {
	log.trace "Inside handleBatteryAlarmReport"

	def result = []
	def deviceName = device.displayName
	def map = null
	switch(cmd.zwaveAlarmEvent) {
		case 0x0A:
			map = [ name: "battery", value: device.currentValue("battery"), descriptionText: "Battery level critical", displayed: true, isStateChange: true ]
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "144", status: "battery level critical",slotnumber:""])
			break
		case 0x0B:
			map = [ name: "battery", value: device.currentValue("battery"), descriptionText: "Battery too low to operate lock", isStateChange: true, displayed: true ]
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "145", status: "battery too low to operate lock",slotnumber:""])
			break
		default:
			// delegating it to handleAlarmReportUsingAlarmType
			return handleAlarmReportUsingAlarmType(cmd)
	}
	
	log.trace "End of handleBatteryAlarmReport"
	result << createEvent(map)
    result
}


/**
 * Responsible for handling AlarmReport commands which are ignored by Access, battery & Burglar handlers
 *
 * @param cmd: The AlarmReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
private def handleAlarmReportUsingAlarmType(cmd) {
	log.trace "Inside handleAlarmReportUsingAlarmType"
	
	def result = []
	def map = null
	
	switch(cmd.alarmType) {
		case 21:  // Manually locked
        	map = [ name: "lock", value: "locked", isStateChange: true ]
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "105", status: "Manually locked", slotnumber:""])
			break
		case 18:  // Locked with keypad, Kwikset lock reporting code id as 0 when locked using the lock keypad button
			map = [ name: "lock", value: "locked", isStateChange: true ]
			//map.data = [ usedCode: cmd.alarmLevel ]
			map.descriptionText = "$device.displayName was locked by keypad"
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "107", status: " Locked with keypad", slotnumber:cmd.alarmLevel])
			break
		case 24:  // Locked by command (Kwikset 914)
			map = [ name: "lock", value: "locked", isStateChange: true ]
			//map.data = [ usedCode: "command" ]
			map.descriptionText = "$device.displayName was locked by command"
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "100", status: " Locked by command", slotnumber:"command"])
			break
		case 27:  // Autolocked
			map = [ name: "lock", value: "locked", isStateChange: true ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "109", status: "Auto Locked",slotnumber:""])
			break
		case 16:  // Note: for levers this means it's unlocked, for non-motorized deadbolt, it's just unsecured and might not get unlocked
		case 19:
			map = [ name: "lock", value: "unlocked", isStateChange: true ]
			if (cmd.alarmLevel) {
				map.descriptionText = "$device.displayName was unlocked with code $cmd.alarmLevel"
                map.value = "unlocked"
                map.data = groovy.json.JsonOutput.toJson([eventTypeId: "108", status: "unlocked",slotnumber: cmd.alarmLevel])
				//map.data = [ usedCode: cmd.alarmLevel ]
			}
			break
		case 22:
		case 25:  // Kwikset 914 unlocked by command
			map = [ name: "lock", value: "unlocked", isStateChange: true ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "103", status: "unlocked",slotnumber:""])
			break
		case 9:
		case 17:
		case 23:
		case 26:
			map = [ name: "lock", value: "unknown", descriptionText: "$device.displayName bolt is jammed", isStateChange: true ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "111", status: "bolt is jammed",slotnumber:""])
			break
		case 13:
			map = [ name: "codeChanged", value: cmd.alarmLevel, descriptionText: "$device.displayName code $cmd.alarmLevel was added", isStateChange: true ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "134", status: "code was added",slotnumber:cmd.alarmLevel])
			result << response(requestCode(cmd.alarmLevel))
			break
		case 32:
			map = [ name: "codeChanged", value: "all", descriptionText: "$device.displayName: all user codes deleted", isStateChange: true ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "135", status: "all user codes deleted",slotnumber:""])
			break
		case 33: // User code deleted
			map = [ name: "codeReport", value: cmd.alarmLevel, data: [ code: "" ], isStateChange: true ]
			map.descriptionText = "$device.displayName code $cmd.alarmLevel was deleted"
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "136", status: "code was deleted",slotnumber:cmd.alarmLevel])
			state["code$cmd.alarmLevel"] = ""
			break
		case 112: 
			map = [ name: "codeChanged", value: cmd.alarmLevel, descriptionText: "$device.displayName code $cmd.alarmLevel changed", isStateChange: true ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "137", status: "code was changed",slotnumber:cmd.alarmLevel])
			result << response(requestCode(cmd.alarmLevel))
			break
		case 34:
		case 113: // Duplicate Pin-code error, mainly sent for master code duplicate		
			map = [ name: "codeChanged", value: "User code failed to add", descriptionText: "$device.displayName: user code not added, duplicate", isStateChange: true ]
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "116", status: "user code not added, duplicate",slotnumber:cmd.alarmLevel])
			break
		case 130:  // Yale YRD batteries replaced
			map = [ name: "battery", value: 0, descriptionText: "$device.displayName batteries replaced", isStateChange: true ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "138", status: "batteries replaced",slotnumber:""])
			break
		case 131: // Disabled code used on keypad
			map = [ /*name: "codeChanged", value: cmd.alarmLevel,*/ descriptionText: "$device.displayName code $cmd.alarmLevel is disabled", isStateChange: true ]
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "139", status: "code is disabled",slotnumber:cmd.alarmLevel])
            break
		case 132: // valid user code used outside of schedule
			map = [ name: "lock", value: device.latestState("lock").value, descriptionText: "Code $cmd.alarmLevel used outside of schedule", isStateChange: true]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "156", status: "Code $cmd.alarmLevel used outside of schedule",slotnumber:cmd.alarmLevel])
			break
		case 161:
			if (cmd.alarmLevel == 2) {
				map = [ descriptionText: "$device.displayName front escutcheon removed", isStateChange: true ]
                map.data = groovy.json.JsonOutput.toJson([eventTypeId: "140", status: "front escutcheon removed",slotnumber:""])
			} else {
				map = [ descriptionText: "$device.displayName detected failed user code attempt", isStateChange: true ]
                map.data = groovy.json.JsonOutput.toJson([eventTypeId: "117", status: "detected failed user code attempt",slotnumber:""])
			}
			break
		case 167:
			if (!state.lastbatt || now() - state.lastbatt > 12*60*60*1000) {
				map = [ descriptionText: "$device.displayName: battery low", isStateChange: true ]
				result << response(secure(zwave.batteryV1.batteryGet()))
                map.data = groovy.json.JsonOutput.toJson([eventTypeId: "142", status: "battery low",slotnumber:""])
			} else {
				map = [ name: "battery", value: device.currentValue("battery"), descriptionText: "$device.displayName: battery low", displayed: true, isStateChange: true ]
                map.data = groovy.json.JsonOutput.toJson([eventTypeId: "143", status: "battery low",slotnumber:""])
			}
			break
		case 168:
			map = [ name: "battery", value: device.currentValue("battery"), descriptionText: "$device.displayName: battery level critical", displayed: true, isStateChange: true ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "144", status: "battery level critical",slotnumber:""])
			break
		case 169:
			map = [ name: "battery", value: device.currentValue("battery"), descriptionText: "$device.displayName: battery too low to operate lock", isStateChange: true ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "145", status: "battery too low to operate lock",slotnumber:""])
			break
        case 98:
			map = [ name: "lock", value: device.latestState("lock").value, descriptionText: "$device.displayName: Scheduling added for slot ${cmd.alarmLevel}", isStateChange: true ]
       		map.data = groovy.json.JsonOutput.toJson([eventTypeId: "162", status: "restriction added",slotnumber: cmd.alarmLevel])
			break
		default:
			map = [ displayed: false, descriptionText: "$device.displayName: alarm event $cmd.alarmType level $cmd.alarmLevel", isStateChange: true ]
            map.data = groovy.json.JsonOutput.toJson([eventTypeId: "146", status: "Generic alarm event ",slotnumber:"",alarmType:cmd.alarmType,alarmLevel:cmd.alarmLevel])
			break
	}
	result << createEvent(map)
	
	log.trace "End of handleAlarmReportUsingAlarmType"
    result
}

/**
 * Responsible for handling UserCodeReport command
 *
 * @param cmd: The UserCodeReport command to be parsed
 *
 * @return 
 *
 */
def zwaveEvent(UserCodeReport cmd) {
	def result = []
	def name = "code$cmd.userIdentifier"
	def code = cmd.code
	def map = [:]
    log.debug "Command received in event $cmd"
	if (cmd.userIdStatus == UserCodeReport.USER_ID_STATUS_OCCUPIED ||
		(cmd.userIdStatus == UserCodeReport.USER_ID_STATUS_STATUS_NOT_AVAILABLE && cmd.user && code != "**********"))
	{
		if (code == "**********") {  // Schlage locks send us this instead of the real code
			state.blankcodes = true
			code = state["set$name"] ?: decrypt(state[name]) ?: code
			state.remove("set$name".toString())
		}
		if (!code && cmd.userIdStatus == 1) {  // Schlage touchscreen sends blank code to notify of a changed code
			map = [ name: "codeChanged", value: groovy.json.JsonOutput.toJson([status: "created",slotnumber: cmd.userIdentifier]), displayed: true, isStateChange: true ]
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "149", status: "created",slotnumber: cmd.userIdentifier])
			map.descriptionText = "$device.displayName code $cmd.userIdentifier " + (state[name] ? "changed" : "was added")
			code = state["set$name"] ?: decrypt(state[name]) ?: "****"
			state.remove("set$name".toString())
            
		} else {
			map = [ name: "codeReport", value: groovy.json.JsonOutput.toJson([status: "created",slotnumber: cmd.userIdentifier,code: code]), data: [ code: code ] ]
			map.data = groovy.json.JsonOutput.toJson([eventTypeId: "150", status: "created",slotnumber: cmd.userIdentifier,code: code])
			map.descriptionText = "$device.displayName code $cmd.userIdentifier is set"
			map.displayed = (cmd.userIdentifier != state.requestCode && cmd.userIdentifier != state.pollCode)
			map.isStateChange = true
            log.debug "Inside else condition in UserCodeReport in unavailable condition"
            map.codeStatusVK = "created"
            map.codeStatusST= cmd.userIdStatus
		}
        log.debug "Sending event map $map" 
		result << createEvent(map)
	} else {
		map = [ name: "codeReport", value: groovy.json.JsonOutput.toJson([status: "reset", slotnumber: cmd.userIdentifier,code: ""]), data: groovy.json.JsonOutput.toJson([eventTypeId: "160", status: "reset",slotnumber: cmd.userIdentifier,code: ""]) ]
		if (state.blankcodes && state["reset$name"]) {  // we deleted this code so we can tell that our new code gets set
			map.descriptionText = "$device.displayName code $cmd.userIdentifier was reset"
			map.displayed = map.isStateChange = true
            //map.codeStatusVK = "reset"
            //map.codeStatusST= cmd.userIdStatus
			result << createEvent(map)
			state["set$name"] = state["reset$name"]
			result << response(setCode(cmd.userIdentifier, state["reset$name"]))
			state.remove("reset$name".toString())
		} else {
			if (state[name]) {
                map.value = groovy.json.JsonOutput.toJson([status: "deleted",slotnumber: cmd.userIdentifier,code: "",code: ""]);
				map.data = groovy.json.JsonOutput.toJson([eventTypeId: "114", status: "deleted",slotnumber: cmd.userIdentifier,code: "",code: ""]);
				map.descriptionText = "$device.displayName code $cmd.userIdentifier was deleted"
                log.debug "Inside else condition for available in UserCodeReport"
                map.codeStatusVK = "deleted"
                map.codeStatusST= cmd.userIdStatus
			} else {
				map.value = groovy.json.JsonOutput.toJson([status: "empty",slotnumber: cmd.userIdentifier,code: ""]);
				map.data = groovy.json.JsonOutput.toJson([eventTypeId: "151", status: "empty",slotnumber: cmd.userIdentifier,code: ""]);
				map.descriptionText = "$device.displayName code $cmd.userIdentifier is not set"
                log.debug "Inside else condition for available in UserCodeReport is not set"
                map.codeStatusVK = "empty"
                map.codeStatusST= cmd.userIdStatus
			}
			map.displayed = (cmd.userIdentifier != state.requestCode && cmd.userIdentifier != state.pollCode)
			map.isStateChange = true
            log.debug "Sending event map $map"
			result << createEvent(map)
		}
		code = ""
	}
	state[name] = code ? encrypt(code) : code

	if (cmd.userIdentifier == state.requestCode) {  // reloadCodes() was called, keep requesting the codes in order
		if (state.requestCode + 1 > state.codes || state.requestCode >= 30) {
			state.remove("requestCode")  // done
		} else {
			state.requestCode = state.requestCode + 1  // get next
			result << response(requestCode(state.requestCode))
		}
	}
	if (cmd.userIdentifier == state.pollCode) {
		if (state.pollCode + 1 > state.codes || state.pollCode >= 30) {
			state.remove("pollCode")  // done
		} else {
			state.pollCode = state.pollCode + 1
		}
	}
	log.debug "code report parsed to ${result.inspect()}"
	result
}


def getMaxSlotsFromLock(){
	log.debug "Inside getMaxSlotsFromLock"
	
	def cmds = []
	state.requestCode = 0
	cmds << secure(zwave.userCodeV1.usersNumberGet())
	cmds;
}


def zwaveEvent(UsersNumberReport cmd) {
	log.debug "Inside zwaveEvent-UsersNumberReport with cmd: $cmd"
	def result = []
	
	state.codes = cmd.supportedUsers
	
	def map = [ name: "lock", descriptionText: "Maximum codes supported : $state.codes", isStateChange: true]
	map.value = device.latestState("lock").value
	map.data = groovy.json.JsonOutput.toJson([eventTypeId: "159", status: "$state.codes", slotnumber:""])
	result << createEvent(map)
	
	if (state.requestCode && state.requestCode <= cmd.supportedUsers) {
		result << response(requestCode(state.requestCode))
	}
	result
}

def zwaveEvent(physicalgraph.zwave.commands.associationv2.AssociationReport cmd) {
	def result = []
	if (cmd.nodeId.any { it == zwaveHubNodeId }) {
		state.remove("associationQuery")
		log.debug "$device.displayName is associated to $zwaveHubNodeId"
		result << createEvent(descriptionText: "$device.displayName is associated")
		state.assoc = zwaveHubNodeId
		if (cmd.groupingIdentifier == 2) {
			result << response(zwave.associationV1.associationRemove(groupingIdentifier:1, nodeId:zwaveHubNodeId))
		}
	} else if (cmd.groupingIdentifier == 1) {
		result << response(secure(zwave.associationV1.associationSet(groupingIdentifier:1, nodeId:zwaveHubNodeId)))
	} else if (cmd.groupingIdentifier == 2) {
		result << response(zwave.associationV1.associationSet(groupingIdentifier:2, nodeId:zwaveHubNodeId))
	}
	result
}

def zwaveEvent(physicalgraph.zwave.commands.timev1.TimeGet cmd) {
	def result = []
	def now = new Date().toCalendar()
	if(location.timeZone) now.timeZone = location.timeZone
	result << createEvent(descriptionText: "$device.displayName requested time update", displayed: false)
	result << response(secure(zwave.timeV1.timeReport(
		hourLocalTime: now.get(Calendar.HOUR_OF_DAY),
		minuteLocalTime: now.get(Calendar.MINUTE),
		secondLocalTime: now.get(Calendar.SECOND)))
	)
	result
}

def zwaveEvent(physicalgraph.zwave.commands.basicv1.BasicSet cmd) {
	// The old Schlage locks use group 1 for basic control - we don't want that, so unsubscribe from group 1
	def result = [ createEvent(name: "lock", value: cmd.value ? "unlocked" : "locked") ]
	result << response(zwave.associationV1.associationRemove(groupingIdentifier:1, nodeId:zwaveHubNodeId))
	if (state.assoc != zwaveHubNodeId) {
		result << response(zwave.associationV1.associationGet(groupingIdentifier:2))
	}
	result
}

def zwaveEvent(physicalgraph.zwave.commands.batteryv1.BatteryReport cmd) {
	def map = [ name: "battery", unit: "%" ]
    log.debug "Battery Map is ${cmd}"
	if (cmd.batteryLevel == 0xFF) {
		map.value = 1
		map.descriptionText = "$device.displayName has a low battery"
	} else {
		map.value = cmd.batteryLevel
        map.isStateChange = true
        map.data = [vkData:[eventTypeId: "147", status: cmd.batteryLevel]]
        //groovy.json.JsonOutput.toJson()
        map.descriptionText = "$device.displayName battery is $cmd.batteryLevel"
	}
	state.lastbatt = now()
    log.debug "Battery Map is ${map}"
	createEvent(map)
}

/**
 * Utility function to update manufacturer field
 */
def updateManufacturerName() {
	log.debug "Inside updateManufacturerName"
	
	if ("003B" == zwaveInfo.mfr) {
		if("Schlage" != getDataValue("manufacturer")) {
			updateDataValue("manufacturer", "Schlage")
		}
	}
	if ("0090" == zwaveInfo.mfr) {
		if("Kwikset" != getDataValue("manufacturer")) {
			updateDataValue("manufacturer", "Kwikset")
		}
	}
	if ("0129" == zwaveInfo.mfr) {
		if("Yale" != getDataValue("manufacturer")) {
			updateDataValue("manufacturer", "Yale")
		}
	}
	if ("022E" == zwaveInfo.mfr) {
		if ("Samsung" != getDataValue("manufacturer")) {
			updateDataValue("manufacturer", "Samsung")
		}
	}
}

/**
 * Utility function to update MSR field
 */
def getMSRFromLock(){
	log.debug "Inside getMSRFromLock"
	
	def cmds = []
	cmds << secure(zwave.manufacturerSpecificV1.manufacturerSpecificGet())
	cmds;
}

/**
 * Responsible for handling Burglar ManufacturerSpecificReport command
 *
 * @param cmd: The ManufacturerSpecificReport command to be parsed
 *
 * @return The event(s) to be sent out
 *
 */
def zwaveEvent(physicalgraph.zwave.commands.manufacturerspecificv2.ManufacturerSpecificReport cmd) {
	def result = []

	def msr = String.format("%04X-%04X-%04X", cmd.manufacturerId, cmd.productTypeId, cmd.productId)
	log.debug "msr: $msr"
	updateDataValue("MSR", msr)
	
	def map = [ name: "lock", descriptionText: "$device.displayName MSR: $msr", isStateChange: true]
	map.value = device.latestState("lock").value
	map.data = groovy.json.JsonOutput.toJson([eventTypeId: "157", status: "$msr", slotnumber:""])
	
	result << createEvent(map)
	updateManufacturerName()
	result
}

def getVersionFromLock(){
	log.debug "Inside getVersionFromLock"
	
	def cmds = []
	cmds << secure(zwave.versionV1.versionGet())
	cmds;
}


def zwaveEvent(physicalgraph.zwave.commands.versionv1.VersionReport cmd) {
	def fw = "${cmd.applicationVersion}.${cmd.applicationSubVersion}"
	updateDataValue("fw", fw)
	def zWaveVersion = "${cmd.zWaveProtocolVersion}.${cmd.zWaveProtocolSubVersion}"
	updateDataValue("Z-Wave", zWaveVersion)
	if (state.MSR == "003B-6341-5044") {
		updateDataValue("ver", "${cmd.applicationVersion >> 4}.${cmd.applicationVersion & 0xF}")
	}
	def text = "$device.displayName: firmware version: $fw, Z-Wave version: ${cmd.zWaveProtocolVersion}.${cmd.zWaveProtocolSubVersion}"

	def map = [ name: "lock", descriptionText: text, isStateChange: true]
	map.value = device.latestState("lock").value
	map.data = groovy.json.JsonOutput.toJson([eventTypeId: "158", status: text, slotnumber:""])


	createEvent(map)
}

def zwaveEvent(physicalgraph.zwave.commands.applicationstatusv1.ApplicationBusy cmd) {
	def msg = cmd.status == 0 ? "try again later" :
	          cmd.status == 1 ? "try again in $cmd.waitTime seconds" :
	          cmd.status == 2 ? "request queued" : "sorry"
	createEvent(displayed: true, descriptionText: "$device.displayName is busy, $msg")
}

def zwaveEvent(physicalgraph.zwave.commands.applicationstatusv1.ApplicationRejectedRequest cmd) {
	createEvent(displayed: true, descriptionText: "$device.displayName rejected the last request")
}

def zwaveEvent(physicalgraph.zwave.Command cmd) {
	log.debug "Inside zwaveEvent"
	createEvent(displayed: false, descriptionText: "$device.displayName: $cmd")
}

/* 
 *	Utility function to parameter name
 */
def getParameterName(parameterName) {
	log.debug "Inside getParameterName"
	
	def result = [:]
	
	if (isSchlageLock()) {
		switch(parameterName) {
        	case 3:
				result.parameterName = "Beeper"
				result.parameterID = 1
				break
        	case 4:
				result.parameterName = "Vacation Mode"
				result.parameterID = 2
				break
        	case 5:
				result.parameterName = "Lock and Leave"
				result.parameterID = 3
				break
        	case 0x0F:
				result.parameterName = "Auto Lock"
				result.parameterID = 4
				break
        	case 0x10:
				result.parameterName = "Pin Length"
				result.parameterID = 5
				break
		}
	}
	else if (isYaleLock()) {
		switch(parameterName) {
        	case 1:
				result.parameterName = "Silent Mode"
				result.parameterID = 6
				break
        	case 2:
				result.parameterName = "Auto Lock"
				result.parameterID = 4
				break
        	case 3:
				result.parameterName = "Auto Lock Time"
				result.parameterID = 7
				break
        	case 4:
				result.parameterName = "Wrong Code Entry Limit"
				result.parameterID = 8
				break
        	case 5:
				result.parameterName = "Language"
				result.parameterID = 9
				break
        	case 7:
				result.parameterName = "Shut Down Time"
				result.parameterID = 10
				break
        	case 8:
				result.parameterName = "Operating Mode"
				result.parameterID = 11
				break
        	case 0x0B:
				result.parameterName = "One Touch Locking"
				result.parameterID = 12
				break
        	case 0x0C:
				result.parameterName = "Privacy Mode"
				result.parameterID = 13
				break
        	case 0x0D:
				result.parameterName = "Lock Status LED"
				result.parameterID = 14
				break
        	case 0x0F:
				result.parameterName = "Factory Reset"
				result.parameterID = 15
				break
		}
	}
	result
}

def zwaveEvent(physicalgraph.zwave.commands.configurationv2.ConfigurationReport cmd){
	log.debug "Inside ConfigurationReport"
    def configParam = getParameterName(cmd.parameterNumber)
    def configValue = cmd.configurationValue[0]
    log.debug "Config Name $configParam "
    log.debug "Config Vale $configValue "
    def map = [:];
    def result = [];
	map.name = "lock"
	map.value = device.latestState("lock").value
	map.isStateChange = true
    map.descriptionText = "Device Config parameters:[$configParam.parameterName, $configValue]"
	map.data = groovy.json.JsonOutput.toJson([eventTypeId: "154", status: "ConfigurationReport", slotnumber: "", parameterName: configParam.parameterName, parameterValue: configValue, parameterID: configParam.parameterID])
    log.debug "Sending event map $map" 
	result = createEvent(map)
    result
}

def lockAndCheck(doorLockMode) {
	secureSequence([
		zwave.doorLockV1.doorLockOperationSet(doorLockMode: doorLockMode),
		zwave.doorLockV1.doorLockOperationGet()
	], 4200)
}

def lock() {
	log.debug "lock is invoked"

    def map = [:];
    def result = [];
	map.name = "lock"
	map.value = device.latestState("lock").value
	map.isStateChange = true
    map.descriptionText = "Device received a lock command from Smartthings"
	map.data = groovy.json.JsonOutput.toJson([eventTypeId: "163", status: device.latestState("lock").value, slotnumber: ""])
    log.debug "Sending event map $map" 
	
	result = sendEvent(map)

	lockAndCheck(DoorLockOperationSet.DOOR_LOCK_MODE_DOOR_SECURED)
}

def lockViaApi() {
	log.debug "lockViaApi is invoked"
	lockAndCheck(DoorLockOperationSet.DOOR_LOCK_MODE_DOOR_SECURED)
   
}

def unlock() {
	log.debug "unlock is invoked"

    def map = [:];
    def result = [];
	map.name = "lock"
	map.value = device.latestState("lock").value
	map.isStateChange = true
    map.descriptionText = "Device received a unlock command from Smartthings"
	map.data = groovy.json.JsonOutput.toJson([eventTypeId: "165", status: device.latestState("lock").value, slotnumber: ""])
    log.debug "Sending event map $map" 
	
	result = sendEvent(map)

	lockAndCheck(DoorLockOperationSet.DOOR_LOCK_MODE_DOOR_UNSECURED)
}

def unlockViaApi() {
	log.debug "unlockViaApi is invoked"
	lockAndCheck(DoorLockOperationSet.DOOR_LOCK_MODE_DOOR_UNSECURED)
}

/**
 * PING is used by Device-Watch in attempt to reach the Device
 */
def ping() {
	log.debug "Executing ping() for device ${device.displayName}"
	runIn(30, followupStateCheck)
	secure(zwave.doorLockV1.doorLockOperationGet())
}

/**
 * Checks the door lock state. Also, schedules checking of door lock state every one hour.
 */
def followupStateCheck() {
	log.debug "Executing followupStateCheck() for device ${device.displayName}"
	runEvery1Hour(stateCheck)
	stateCheck()
}

/**
 * Checks the door lock state
 */
def stateCheck() {
	log.debug "Executing stateCheck() for device ${device.displayName}"
	sendHubCommand(new physicalgraph.device.HubAction(secure(zwave.doorLockV1.doorLockOperationGet())))
}

def unlockwtimeout() {
	lockAndCheck(DoorLockOperationSet.DOOR_LOCK_MODE_DOOR_UNSECURED_WITH_TIMEOUT)
}

def displaystatedb() {
	def map = [ name: "reportAllCodes", data: [:], displayed: false, isStateChange: false, type: "physical" ]
	state.each { entry ->
		//iterate through all the state entries and add them to the event data to be handled by application event handlers
		if ( entry.key ==~ /^code\d{1,}/ && entry.value.startsWith("~") ) {
			map.data.put(entry.key, decrypt(entry.value))
		} else {
			map.data.put(entry.key, entry.value)
		}
	}
	log.debug " Prnting Map is ${map}"
}

def refresh() {
	def cmds = secureSequence([zwave.doorLockV1.doorLockOperationGet(), zwave.batteryV1.batteryGet()])
	if (state.assoc == zwaveHubNodeId) {
		log.debug "$device.displayName is associated to ${state.assoc}"
	} else if (!state.associationQuery) {
		log.debug "checking association"
		cmds << "delay 4200"
		cmds << zwave.associationV1.associationGet(groupingIdentifier:2).format()  // old Schlage locks use group 2 and don't secure the Association CC
		cmds << secure(zwave.associationV1.associationGet(groupingIdentifier:1))
		state.associationQuery = now()
	} else if (secondsPast(state.associationQuery, 9)) {
		cmds << "delay 6000"
		cmds << zwave.associationV1.associationSet(groupingIdentifier:2, nodeId:zwaveHubNodeId).format()
		cmds << secure(zwave.associationV1.associationSet(groupingIdentifier:1, nodeId:zwaveHubNodeId))
		cmds << zwave.associationV1.associationGet(groupingIdentifier:2).format()
		cmds << secure(zwave.associationV1.associationGet(groupingIdentifier:1))
		state.associationQuery = now()
	}
	log.debug "refresh sending ${cmds.inspect()}"
	cmds
}

def getBatteryLevelFromLock(){
	def cmds = []
	cmds << secure(zwave.batteryV1.batteryGet())
	cmds;
}

def poll() {
	def cmds = []
	// Only check lock state if it changed recently or we haven't had an update in an hour
	def latest = device.currentState("lock")?.date?.time
	if (!latest || !secondsPast(latest, 6 * 60) || secondsPast(state.lastPoll, 55 * 60)) {
		cmds << secure(zwave.doorLockV1.doorLockOperationGet())
		state.lastPoll = now()
	} else if (!state.lastbatt || now() - state.lastbatt > 53*60*60*1000) {
		cmds << secure(zwave.batteryV1.batteryGet())
		state.lastbatt = now()  //inside-214
	}
	
	if (!state.MSR) {
		cmds << zwave.manufacturerSpecificV1.manufacturerSpecificGet().format()
	} else if (!state.fw) {
		cmds << zwave.versionV1.versionGet().format()
	} else if (!device.currentValue("maxCodes")) {
		state.requestCode = 0
		cmds << secure(zwave.userCodeV1.usersNumberGet())
	}
	
	if (cmds) {
		log.debug "poll is sending ${cmds.inspect()}"
		cmds
	} else {
		// workaround to keep polling from stopping due to lack of activity
		sendEvent(descriptionText: "skipping poll", isStateChange: true, displayed: false)
		null
	}
	
}

def requestCode(codeNumber) {
	log.debug "requesting code for $codeNumber";
	secure(zwave.userCodeV1.userCodeGet(userIdentifier: codeNumber))
}

def reloadAllCodes() {

	log.debug "reloadAllCodes is called"
	def cmds = []
    
    state.remove("requestCode")
    
   log.debug "reloadAllCodes cmds is $state.codes" 
	if (!state.codes) {
		state.requestCode = 1
		cmds << secure(zwave.userCodeV1.usersNumberGet())
	} else {
		if(!state.requestCode) state.requestCode = 1
		cmds << requestCode(state.requestCode)
	}
	cmds
}

def setCode(number, code) {
	int codeNumber = number;
	String strcode = code;//Integer.toString(codeInt);
    

    log.debug "setting code $codeNumber to $strcode"
  
        if (isDanaLock()) {
            log.debug "Lock type is Danalock, Setting the code directly without issuing a delete"
            state["setcode$codeNumber"] = strcode
        }
        else{
            // Can't just set, we won't be able to tell if it was successful
            if (state["code$codeNumber"] != "") {
                if (state["setcode$codeNumber"] != strcode) {
                    state["resetcode$codeNumber"] = strcode
                    return deleteCode(codeNumber)
                }
            } else {
                log.debug "Create new code $codeNumber to $strcode"
                state["setcode$codeNumber"] = strcode
            }
        }
	
	secureSequence([
		zwave.userCodeV1.userCodeSet(userIdentifier:codeNumber, userIdStatus:1, user:strcode),
		zwave.userCodeV1.userCodeGet(userIdentifier:codeNumber)
	], 7000)
}


def deleteCode(codeNumber) {
	log.debug "deleting code $codeNumber"
                     
	secureSequence([
		zwave.userCodeV1.userCodeSet(userIdentifier:codeNumber, userIdStatus:0),
		zwave.userCodeV1.userCodeGet(userIdentifier:codeNumber)
	], 7000)
}

def getCode(codeNumber) {
	decrypt(state["code$codeNumber"])
}

def getAllCodes() {
	state.findAll { it.key.startsWith 'code' }.collectEntries {
		[it.key, (it.value instanceof String && it.value.startsWith("~")) ? decrypt(it.value) : it.value]
	}
}

private secure(physicalgraph.zwave.Command cmd) {
	zwave.securityV1.securityMessageEncapsulation().encapsulate(cmd).format()
}

private secureSequence(commands, delay=4200) {
	delayBetween(commands.collect{ secure(it) }, delay)
}

private Boolean secondsPast(timestamp, seconds) {
	if (!(timestamp instanceof Number)) {
		if (timestamp instanceof Date) {
			timestamp = timestamp.time
		} else if ((timestamp instanceof String) && timestamp.isNumber()) {
			timestamp = timestamp.toLong()
		} else {
			return true
		}
	}
	return (now() - timestamp) > (seconds * 1000)
}

include 'asynchttp_v1'

def responseHandlerMethod(response, data) {
    log.debug "got response data: ${response.getData()}"
    log.debug "data map passed to handler method is: $data"
}


/**
 * Get the current schedule time offset (timezone) setting from the device.
 *
 * @return
 */
def getScheduleTimeOffset() {
    log.debug("getScheduleTimeOffset()")
    def cmd = secure(zwave.scheduleEntryLockV3.scheduleEntryLockTimeOffsetGet())
    log.debug("getScheduleTimeOffset: $cmd")
    cmd
}

/**
 * Set the schedule time offset (timezone) on the device.
 *
 * @return
 */
def setScheduleTimeOffset() {
    log.debug("setScheduleTimeOffset()")

      def map = [ hourTzo   : 0,
            minuteOffsetDst : 0,
            minuteTzo  : 0,
            signOffsetDst : 0,
            signTzo   : 0 ]       

    log.debug("setTimeOffset: $map")

    secureSequence([
		zwave.scheduleEntryLockV3.scheduleEntryLockTimeOffsetSet(map),
		zwave.scheduleEntryLockV3.scheduleEntryLockTimeOffsetGet()
	], 3000)
}


/**
 *
 * @param cmd
 * @return
 */
def zwaveEvent(physicalgraph.zwave.commands.scheduleentrylockv3.ScheduleEntryLockTimeOffsetReport cmd) {
/*
Short hourTzo
Short minuteOffsetDst
Short minuteTzo
Boolean signOffsetDst
Boolean signTzo
*/
    log.debug("ScheduleEntryLockTimeOffsetReport $cmd")
    if (state.time == null) {
        state.time = [:]
    }
    state.time.offset = [ hourTzo: cmd.hourTzo,
            minuteOffsetDst: cmd.minuteOffsetDst,
            minuteTzo: cmd.minuteTzo,
            signOffsetDst: cmd.signOffsetDst,
            signTzo: cmd.signTzo ]
    def map = [:];
    def result = [];
	map.name = "lock"
	map.value = device.latestState("lock").value
	map.isStateChange = true
    map.descriptionText = "Lock internal Time Offset : $cmd.hourTzo, $cmd.minuteOffsetDst, $cmd.minuteTzo, $cmd.signOffsetDst, $cmd.signTzo"
	map.data = groovy.json.JsonOutput.toJson([eventTypeId: "155", status: "TimeZoneParamReport", slotnumber: "", hourTzo: cmd.hourTzo, minuteTzo: cmd.minuteTzo, minuteOffsetDst: cmd.minuteOffsetDst, signOffsetDst: cmd.signOffsetDst, signTzo: cmd.signTzo])
    log.debug "Sending event map $map" 
	result = createEvent(map)
    result
}

/**
 * Get the types off schedules supported and how many for each user.
 *
 * @return
 */
def getScheduleEntryTypeSupported() {
    secure(zwave.scheduleEntryLockV3.scheduleEntryTypeSupportedGet())
}


def setYearDayScheduleAPI(userIdentifier, slot,
                       startDay, startHour, startMinute, startMonth, startYear,
                       stopDay, stopHour, stopMinute, stopMonth, stopYear){
	log.debug(" setYearDayScheduleAPI invoked");

	log.debug(" setYearDayScheduleAPI is invoked $userIdentifier  $slot $startDay $startHour $startMinute $startMonth $startYear $stopDay $stopHour $stopMinute $stopMonth $stopYear");
    
    def cmd = null;
    def map = [ startDay: startDay,
                startHour: startHour,
                startMinute: startMinute,
                startMonth: startMonth,
                startYear: startYear,
                stopDay: stopDay,
                stopHour: stopHour,
                stopMinute: stopMinute,
                stopMonth: stopMonth,
                stopYear: stopYear,
                setAction: 1,
                scheduleSlotId: 1,
                userIdentifier: userIdentifier ]

	cmd = secureSequence([zwave.scheduleEntryLockV3.scheduleEntryLockYearDaySet(map),
                zwave.scheduleEntryLockV3.scheduleEntryLockYearDayGet(userIdentifier: userIdentifier, scheduleSlotId: 1)])                
    return cmd

}


/**
 *
 * @param cmd
 * @return
 */
def zwaveEvent(physicalgraph.zwave.commands.scheduleentrylockv3.ScheduleEntryTypeSupportedReport cmd) {
/*
Short numberOfSlotsDailyRepeating
Short numberOfSlotsWeekDay
Short numberOfSlotsYearDay
*/
    log.debug("ScheduleEntryTypeSupportedReport: $cmd")
    if (state.codeSchedule == null) {
        state.codeSchedule = [:]
    }
    if (state.codeSchedule.numberOfSlots == null) {
        state.codeSchedule.numberOfSlots = [:]
    }

    state.codeSchedule.numberOfSlots.dailyRepeating = cmd.numberOfSlotsDailyRepeating
    state.codeSchedule.numberOfSlots.weekDay = cmd.numberOfSlotsWeekDay
    state.codeSchedule.numberOfSlots.yearDay = cmd.numberOfSlotsYearDay

    createEvent(name: "scheduleTypes", value: state.codeSchedule.numberOfSlots)
}



/**
 *
 * @param cmd
 * @return
 */
def zwaveEvent(physicalgraph.zwave.commands.scheduleentrylockv3.ScheduleEntryLockYearDayReport  cmd) {
/*
Short scheduleSlotId
Short startDay
Short startHour
Short startMinute
Short startMonth
Short startYear
Short stopDay
Short stopHour
Short stopMinute
Short stopMonth
Short stopYear
Short userIdentifier
*/
    log.debug("ScheduleEntryLockYearDayReport $cmd")
/*    def map = [ startDay: cmd.startDay,
            startHour: cmd.startHour,
            startMinute: cmd.startMinute,
            startMonth: cmd.startMonth,
            startYear: cmd.startYear,
            stopDay: cmd.stopDay,
            stopHour: cmd.stopHour,
            stopMinute: cmd.stopMinute,
            stopMonth: cmd.stopMonth,
            stopYear: cmd.stopYear,
            userIdentifier: cmd.userIdentifier ]
    scheduleEvent(cmd.userIdentifier, cmd.scheduleSlotId, map, "yearDay")*/
    
    def map = [:];
    def result = [];
	map.name = "lock"
	map.value = device.latestState("lock").value
	map.isStateChange = true
    
    if (cmd.startMinute == 255 && cmd.startHour == 255 && cmd.startDay == 255 && cmd.startMonth == 255 && cmd.startYear == 255 && 
    		cmd.stopMinute == 255 && cmd.stopHour == 255 && cmd.stopDay == 255 && cmd.stopMonth == 255 && cmd.stopYear == 255) {
		map.descriptionText = "$device.displayName: Scheduling cleared for slot ${cmd.userIdentifier}"
   		map.data = groovy.json.JsonOutput.toJson([eventTypeId: "161", status: "No restriction", slotnumber: cmd.userIdentifier])
    } else {        
	    map.descriptionText = "$device.displayName: Scheduling added for slot ${cmd.userIdentifier}"
   		map.data = groovy.json.JsonOutput.toJson([eventTypeId: "152", status: "restriction added", slotnumber: cmd.userIdentifier, startMinute: cmd.startMinute, startHour: cmd.startHour, startDay: cmd.startDay, startMonth: cmd.startMonth, startYear: cmd.startYear, stopMinute: cmd.stopMinute, stopHour: cmd.stopHour, stopDay: cmd.stopDay, stopMonth: cmd.stopMonth,  stopYear: cmd.stopYear])
    }
	result = createEvent(map)
    log.debug "Sending event map $result"
    result
    
}





/**
 *
 * @param cmd
 * @return
 */
def zwaveEvent(physicalgraph.zwave.commands.scheduleentrylockv3.ScheduleEntryLockDailyRepeatingReport cmd) {
/*
Short durationHour
Short durationMinute
Short scheduleSlotId
Short startHour
Short startMinute
Short userIdentifier
Short weekDayBitmask
*/
    log.debug("ScheduleEntryLockDailyRepeatingReport $cmd")
    if (cmd.startHour == 0xFF) {
        scheduleEventDelete(cmd.userIdentifier, cmd.scheduleSlotId, "dailyRepeating")
    } else {
        def map = [ durationHour: cmd.durationHour,
                durationMinute: cmd.durationMinute,
                startHour: cmd.startHour,
                startMinute: cmd.startMinute,
                userIdentifier: cmd.userIdentifier,
                weekDayBitmask: cmd.weekDayBitmask ]
        scheduleEvent(cmd.userIdentifier, cmd.scheduleSlotId, map, "dailyRepeating")
    }
}

/**
 *
 * @param cmd
 * @return
 */
def zwaveEvent(physicalgraph.zwave.commands.scheduleentrylockv3.ScheduleEntryLockWeekDayReport  cmd) {
/*
Short dayOfWeek
Short scheduleSlotId
Short startHour
Short startMinute
Short stopHour
Short stopMinute
Short userIdentifier
*/
    log.debug("ScheduleEntryLockWeekDayReport $cmd")
    def map = [ dayOfWeek: cmd.dayOfWeek,
            startHour: cmd.startHour,
            startMinute: cmd.startMinute,
            stopHour: cmd.stopHour,
            stopMinute: cmd.stopMinute,
            userIdentifier: cmd.userIdentifier ]
    scheduleEvent(cmd.userIdentifier, cmd.scheduleSlotId, map, "weekDay")
}


/**
 * Get a year day schedule.
 *
 * @param userIdentifier
 * @param slot
 * @return
 */
def getYearDaySchedule(userIdentifier, slot) {
	log.debug(" getYearDaySchedule $userIdentifier  slot is $slot ");
	short userIdentifierShort = userIdentifier;
	short slotshort = slot;
    
    secure(zwave.scheduleEntryLockV3.scheduleEntryLockYearDayGet(userIdentifier: userIdentifier, scheduleSlotId: slot));
}


/**
 *
 * @param cmd
 * @return
 */
def zwaveEvent(physicalgraph.zwave.commands.timeparametersv1.TimeParametersReport cmd) {
/*
Short day
Short hourUtc
Short minuteUtc
Short month
Short secondUtc
Integer year
*/

    // Track the delta between the time in the report and the current time,
    // so that we can display device time without constantly querying for
    // the current value.

    def now = new Date()

    log.debug("TimeParametersReport: $cmd")
    /*def timeParams = [ year   : now[YEAR]         - cmd.year,
            month  : now[MONTH]        - cmd.month,
            day    : now[DAY_OF_MONTH] - cmd.day,
            hour   : now[HOUR_OF_DAY]  - cmd.hourUtc,
            minute : now[MINUTE]       - cmd.minuteUtc,
            second : now[SECOND]       - cmd.secondUtc ]
    if (state.time == null) {
        state.time = [:]
    }
	state.time.delta = timeParams*/
    def map = [:];
    def result = [];
	map.name = "lock"
	map.value = device.latestState("lock").value
	map.isStateChange = true
	map.descriptionText = "Lock internal time set to $cmd.year-$cmd.month-$cmd.day $cmd.hourUtc:$cmd.minuteUtc:$cmd.secondUtc"
	map.data = groovy.json.JsonOutput.toJson([eventTypeId: "153", status: "report", slotnumber: "", setTimestamp: cmd.year+"-"+cmd.month+"-"+cmd.day+" "+cmd.hourUtc+":"+cmd.minuteUtc+":"+cmd.secondUtc])
	result = createEvent(map)
    log.debug "Sending event map $result"
    result
}

/*
 *
 * Time Parameters Command Class (V1)
 *
 */

/**
 * Get the date and time settings from the device.
 *
 * @return
 */
def getTimeParameters() {
    log.debug("getTimeParameters()")
    secure(zwave.timeParametersV1.timeParametersGet())
}


/**
 * Set the [UTC] date and time on the device.
 * @return
 */
def setTimeParameters() {
/*
Short day
Short hourUtc
Short minuteUtc
Short month
Short secondUtc
Integer year
*/

    log.debug("setTimeParameters()")
    def now = new Date()
    def map = [ day : now[DAY_OF_MONTH],
            hourUtc : now[HOUR_OF_DAY],
            minuteUtc : now[MINUTE],
            month : now[MONTH]+1,
            secondUtc : now[SECOND],
            year : now[YEAR] ]
	log.debug ("now is $now");
	log.debug("setTimeParameters() ${map}")
    
	secureSequence([
		zwave.timeParametersV1.timeParametersSet(map),
		zwave.timeParametersV1.timeParametersGet()
	], 3000)
}

/**
 * Called on app installed
 */
def installed() {
	// Device-Watch pings if no device events received for 1 hour (checkInterval)
	sendEvent(name: "checkInterval", value: 1 * 60 * 60, displayed: false, data: [protocol: "zwave", hubHardwareId: device.hub.hardwareID, offlinePingable: "1"])

}


/**
 * Utility function to check if the lock manufacturer is Schlage
 *
 * @return true if the lock manufacturer is Schlage, else false
 */
def isSchlageLock() {
	if ("003B" == zwaveInfo.mfr) {
		if("Schlage" != getDataValue("manufacturer")) {
			updateDataValue("manufacturer", "Schlage")
		}
		return true
	}
	return false
}

/**
 * Utility function to check if the lock manufacturer is Kwikset
 *
 * @return true if the lock manufacturer is Kwikset, else false
 */
def isKwiksetLock() {
	if ("0090" == zwaveInfo.mfr) {
		if("Kwikset" != getDataValue("manufacturer")) {
			updateDataValue("manufacturer", "Kwikset")
		}
		return true
	}
	return false
}

/**
 * Utility function to check if the lock manufacturer is Yale
 *
 * @return true if the lock manufacturer is Yale, else false
 */
def isYaleLock() {
	if ("0129" == zwaveInfo.mfr) {
		if("Yale" != getDataValue("manufacturer")) {
			updateDataValue("manufacturer", "Yale")
		}
		return true
	}
	return false
}

/**
 * Utility function to check if the lock manufacturer is Samsung
 *
 * @return true if the lock manufacturer is Samsung, else false
 */
private isSamsungLock() {
	if ("022E" == zwaveInfo.mfr) {
		if ("Samsung" != getDataValue("manufacturer")) {
			updateDataValue("manufacturer", "Samsung")
		}
		return true
	}
	return false
}


/**
 * Clear a schedule slot.
 *
 * @param userIdentifier
 * @param slot
 * @param type
 * @return
 */

def clearYearDaySchedule(userIdentifier, slot) {
	log.debug(" clearYearDaySchedule $userIdentifier  slot is $slot ");
    
/*    secure(zwave.scheduleEntryLockV3.scheduleEntryLockYearDayGet(userIdentifier: userIdentifier, scheduleSlotId: slot));
    secure(zwave.scheduleEntryLockV3.scheduleEntryLockYearDayGet(userIdentifier: userIdentifier, scheduleSlotId: slot));
  */  
    secureSequence([zwave.scheduleEntryLockV3.scheduleEntryLockYearDaySet(userIdentifier: userIdentifier, scheduleSlotId: slot, setAction: 0),
            zwave.scheduleEntryLockV3.scheduleEntryLockYearDayGet(userIdentifier: userIdentifier, scheduleSlotId: slot)])

}



def clearAllYearDaySchedule(slot){
	log.debug "Inside clearAllYearDaySchedule for all slots with schedule Slot Id $slot";
    def commands = [];
	
    
	for (int i=1;i<=state.codes;i++){
        commands << zwave.scheduleEntryLockV3.scheduleEntryLockYearDaySet(userIdentifier: i, scheduleSlotId: slot, setAction: 0);
        commands << zwave.scheduleEntryLockV3.scheduleEntryLockYearDayGet(userIdentifier: i, scheduleSlotId: slot);
	}
    
	delayBetween(commands.collect{ secure(it) }, 7000);
    
    
}

def zwaveEvent(physicalgraph.zwave.commands.notificationv3.NotificationReport cmd) {
	log.debug "Inside zwaveEvent-NotificationReport, parsing NotificationReport command = $cmd"
    
    log.debug("mapping to AlarmType");
    def newCmd = new physicalgraph.zwave.commands.alarmv2.AlarmReport(
    	eventParameter: cmd.eventParameter,
        numberOfEventParameters: cmd.eventParametersLength,
        zensorNetSourceNodeId: cmd.zensorNetSourceNodeId,
        zwaveAlarmType: cmd.notificationType,
        alarmLevel: cmd.v1AlarmLevel,
        zwaveAlarmStatus: cmd.notificationStatus,
        zwaveAlarmEvent: cmd.event,
        alarmType: cmd.v1AlarmType
    )
    
    log.debug("Calling alarmV2.AlarmReport function")
    zwaveEvent(newCmd)
}

/**
 * Utility function to check if the lock manufacturer is Dana
 *
 * @return true if the lock manufacturer is Dana, else false
 */
def isDanaLock() {
	if ("010E" == zwaveInfo.mfr) {
		if("Danalock" != getDataValue("manufacturer")) {
			updateDataValue("manufacturer", "Danalock")
		}
		return true
	}
	return false
}

/**
 * Responsible for disabling Privacy Mode on Yale Locks
 */
def disablePrivacyButtonOnYale() {
	log.debug "Inside disablePrivacyButtonOnYale"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 12, size: 1, configurationValue: [ 0x00 ]),
		zwave.configurationV2.configurationGet(parameterNumber: 12) ], 3000)
}

/**
 * Responsible for disabling Privacy Mode on Yale Locks
 */
def enablePrivacyButtonOnYale() {
	log.debug "Inside enablePrivacyButtonOnYale"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 12, size: 1, configurationValue: [ 0xFF ]),
		zwave.configurationV2.configurationGet(parameterNumber: 12) ], 3000)
}

/**
 * Responsible for disabling Privacy Mode on Yale Locks
 */
def setOperatingModeToNormalOnYale() {
	log.debug "Inside setOperatingModeToNormalOnYale"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 8, size: 1, configurationValue: [ 0x00 ]),
		zwave.configurationV2.configurationGet(parameterNumber: 8) ], 3000)
}

/**
 * Responsible for setting Vacation Mode on Yale Locks
 */
def setOperatingModeToVacationOnYale() {
	log.debug "Inside setOperatingModeToVacationOnYale"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 8, size: 1, configurationValue: [ 0x01 ]),
		zwave.configurationV2.configurationGet(parameterNumber: 8) ], 3000)
}

/**
 * Responsible for setting Privacy Mode on Yale Locks
 */
def setOperatingModeToPrivacyOnYale() {
	log.debug "Inside setOperatingModeToPrivacyOnYale"
	secureSequence([ zwave.configurationV2.configurationSet(parameterNumber: 8, size: 1, configurationValue: [ 0x02 ]),
		zwave.configurationV2.configurationGet(parameterNumber: 8) ], 3000)
}
