# https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/MAX_SAFE_INTEGER
# we don't use sys.maxint (= 2 ** 63 - 1) as this spec is in line with the ILP JavaScript reference implementation
# see https://interledger.org/
MAX_SAFE_INTEGER_JS = 2 ** 53 - 1


class TypeRegistry:
    """ """
    registered_types = []

    @staticmethod
    def get_class_from_type_id(type_id):
        """
        Determine fulfillment implementation class from a bitmask.

        Returns the class implementing a fulfillment type that matches a certain type ID.

        Args:
            type_id (int): fulfillment type ID

        Return:
            Class implementing the given fulfillment type.
        """
        # Determine type of condition
        if type_id > MAX_SAFE_INTEGER_JS:
            raise ValueError('Type {} is not supported'.format(type_id))

        for registered_type in TypeRegistry.registered_types:
            if type_id == registered_type['type_id']:
                return registered_type['class']

        raise ValueError('Type {} is not supported'.format(type_id))

    @staticmethod
    def register_type(cls):
        """
        Add a new fulfillment type.

        This can be used to extend this cryptocondition implementation with new
        fulfillment types that it does not yet support. But mostly it is used
        internally to register the built-in types.

        In this method, we expect a regular fulfillment type, for information on
        registering meta types please see `registerMetaType`.

        Args:
           cls: Implementation of a fulfillment type.
        """
        # TODO Do some sanity checks on Class

        TypeRegistry.registered_types.append(
            {
                'type_id': cls.TYPE_ID,
                'class': cls
            })



