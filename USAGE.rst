=====
Usage
=====


To use lastpasslib in a project:

.. code-block:: python

    from lastpasslib import Lastpass
    lastpass = Lastpass(USERNAME, PASSWORD, MFA)

    # Just showing a fragment of info exposed.

    # iterate through all secrets:
    for secret in lastpass.get_secrets():
        print(secret.name)
        # if a secret is shared print the info
        if secret.shared_to_people:
            for share in secret.shared_to_people:
                print(share)
        # if the secret type is password print note, username and password history if any.
        if secret.type == 'Password':
            if secret.note_history:
                for history in secret.note_history:
                    print(history)
            if secret.username_history:
                for history in secret.username_history:
                    print(history)
            if secret.password_history:
                for history in secret.password_history:
                    print(history)
        else:
            # else it is a secure note type so print any history it has
            if secret.history:
                for history in secret.history:
                    print(history)

