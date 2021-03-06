from zExceptions import Unauthorized
if REQUEST is not None:
  raise Unauthorized

if context.getAggregate() is not None:
  raise ValueError('Do not destroy allocated instances automatically!')

# Change desired state
promise_kw = {
    'instance_xml': context.getTextContent(),
    'software_type': context.getSourceReference(),
    'sla_xml': context.getSlaXml(),
    'software_release': context.getUrlString(),
    'shared': context.getPortalType()=="Slave Instance",
  }

request_software_instance_url = context.getRelativeUrl()
context.REQUEST.set('request_instance', context)

context.requestDestroy(**promise_kw)

title = context.getTitle()
context.setTitle(title + "_renamed_and_destroyed")

context.REQUEST.set('request_instance', None)
