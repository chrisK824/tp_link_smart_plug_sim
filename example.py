
from TPLinkPlug import TPLink
from time import sleep

mytpLink = TPLink(alias="PythonSimulatedHS110", model="HS110(UK)", mac="50:c7:bf:c5:86:b2")
mytpLink.simulate_plug_in(power = 1420, voltage = 227, current = 2.6)
mytpLink.turn_relay_on()
sleep(60)
mytpLink.turn_relay_off()
mytpLink.simulate_plug_out()