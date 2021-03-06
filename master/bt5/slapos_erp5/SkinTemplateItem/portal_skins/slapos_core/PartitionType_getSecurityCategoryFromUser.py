"""
This script returns a list of dictionaries which represent
the security groups which a person is member of. It extracts
the categories from the current content. It is useful in the
following cases:

- calculate a security group based on a given
  category of the current object (ex. group). This
  is used for example in ERP5 DMS to calculate
  document security.

- assign local roles to a document based on
  the person which the object related to through
  a given base category (ex. destination). This
  is used for example in ERP5 Project to calculate
  Task / Task Report security.

The parameters are

  base_category_list -- list of category values we need to retrieve
  user_name          -- string obtained from getSecurityManager().getUser().getId()
  object             -- object which we want to assign roles to
  portal_type        -- portal type of object

NOTE: for now, this script requires proxy manager
"""

category_list = []

if obj is None:
  return []

partition = obj
for instance in partition.getPortalObject().portal_catalog(
    portal_type=["Software Instance", "Slave Instance"],
    validation_state="validated",
    default_aggregate_uid=partition.getUid()):
  if instance is not None:
    hosting_subscription = instance.getSpecialiseValue(portal_type="Hosting Subscription")
    if hosting_subscription is not None:
      person = hosting_subscription.getDestinationSectionValue(portal_type="Person")
      if person is not None:
        for base_category in base_category_list:
          category_list.append({base_category: [person.getRelativeUrl()]})

return category_list
