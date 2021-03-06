from Products.ERP5Form.Report import ReportSection
result = []

event_list = context.Ticket_getFollowUpRelatedEventList(sort_on=[('delivery.start_date', 'ASC'),])
for event in event_list:
  result.append(
    ReportSection(
      path=event.getPhysicalPath(),
      form_id='Event_viewRawDescription',
      )
  )

return result
