class LastpassMock:

    def __init__(self, username, domain='lastpass.com'):
        self.domain = domain
        self.host = f'https://{domain}'
        self.username = username
        self.iteration_count = 100100