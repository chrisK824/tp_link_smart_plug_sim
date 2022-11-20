
from TPLinkPlug import TPLink


mytpLink = TPLink(alias="PlugSimPython", mac="50:c7:bf:c5:86:bd")
mytpLink.simulate_plug_in(power = 1420, voltage = 227, current = 2.6)
