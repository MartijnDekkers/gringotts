import sys
import inspect
import click
import logging
import hashlib
import os
import requests
import tarfile
import zipfile
import re
import bs4

# Setup the logger
logger = logging.getLogger('gringott')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')


# Function to setup file and screen logging
def setup_logging(log, debug, log_directory=None):
    if log is True:
        if log_directory is None:
            log_directory = '.'
        file_handler = logging.FileHandler(f'{log_directory}/gringott.log')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    if debug is True:
        console_handler = logging.StreamHandler()
        logger.addHandler(console_handler)


def print_debug(msg, *args):
    """Function to log debug messages."""
    caller = inspect.getframeinfo(sys._getframe(1))
    thisfile = os.path.splitext(os.path.basename(caller.filename))[0]
    logger.debug(f'DEBUG: {thisfile}:{caller.lineno}, Func: \033[1m{caller.function}\033[0m, Msg: \033[1m{msg}\033[0m, Args: {args}')


def get_latest_version(ctx, service):
    consul_version = None
    vault_version = None

    if ctx.obj['DEBUG'] is True:
        print_debug('get_latest_version called...', service)

    if service == 'vault' or service == 'all':
        releases_url = 'https://releases.hashicorp.com/vault/'
        response = requests.get(releases_url)
        if response.ok:
            soup = bs4.BeautifulSoup(response.content, 'html.parser')
            version_links = soup.find_all('a', href=True)
            version_numbers = [re.search(r'/vault/([\d\.]+)/', link['href']).group(1) for link in version_links if
                               re.search(r'/vault/([\d\.]+)/', link['href'])]
            version_numbers.sort(key=lambda s: list(map(int, s.split('.'))))
            vault_version = version_numbers[-1]
            if ctx.obj['DEBUG'] is True:
                print_debug(f'Latest version of Vault is {vault_version}')
        else:
            print_debug('Could not fetch versions from HashiCorp Vault releases page.')
            raise Exception('Could not fetch versions from HashiCorp Vault releases page.')

    if service == 'consul' or service == 'all':
        releases_url = 'https://releases.hashicorp.com/consul/'
        response = requests.get(releases_url)
        if response.ok:
            soup = bs4.BeautifulSoup(response.content, 'html.parser')
            version_links = soup.find_all('a', href=True)
            version_numbers = [re.search(r'/consul/([\d\.]+)/', link['href']).group(1) for link in version_links if
                               re.search(r'/consul/([\d\.]+)/', link['href'])]
            version_numbers.sort(key=lambda s: list(map(int, s.split('.'))))
            consul_version = version_numbers[-1]
            if ctx.obj['DEBUG'] is True:
                print_debug(f'Latest version of Consul is {consul_version}')
        else:
            print_debug('Could not fetch versions from HashiCorp Consul releases page.')
            raise Exception('Could not fetch versions from HashiCorp Consul releases page.')

    return vault_version, consul_version


def construct_download_url(ctx):
    if ctx.obj['DEBUG'] is True:
        print_debug('construct_download_url entered', ctx.obj)

    service = ctx.obj['dl_service']
    os_name = ctx.obj['dl_os']
    architecture = ctx.obj['dl_arch']
    consul_version = ctx.obj['url_consul_version']
    vault_version = ctx.obj['url_vault_version']

    consul_url = None
    vault_url = None

    if (service == 'consul' or service == 'all') and consul_version is not None:
        base_url = 'https://releases.hashicorp.com/consul/{}/consul_{}_{}_{}.zip'
        consul_url = base_url.format(consul_version, consul_version, os_name, architecture)
        if ctx.obj['DEBUG'] is True:
            print_debug(f'Consul download URL: {consul_url}')

    if (service == 'vault' or service == 'all') and vault_version is not None:
        base_url = 'https://releases.hashicorp.com/vault/{}/vault_{}_{}_{}.zip'
        vault_url = base_url.format(vault_version, vault_version, os_name, architecture)
        if ctx.obj['DEBUG'] is True:
            print_debug(f'Vault download URL: {vault_url}')

    return consul_url, vault_url


# Download the required binary
def download_binary(ctx, url, destination):
    if ctx.obj['DEBUG'] is True:
        print_debug('download_binary entered', ctx.obj)

    response = requests.get(url, stream=True)
    if response.ok:
        filename = url.split('/')[-1]
        destination_path = os.path.join(destination, filename)
        with open(destination_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return destination_path
    else:
        raise Exception('Failed to download  file.')


# Validate the checksum
def validate_checksum(ctx, cs_service, file_path, version, checksum_url=None, provided_checksum_file=None):
    if ctx.obj['DEBUG'] is True:
        print_debug('validate_checksum entered', ctx.obj)

    if provided_checksum_file:
        with open(provided_checksum_file, 'r') as f:
            checksums = f.read()
    else:
        if checksum_url is None:
            checksum_url = f'https://releases.hashicorp.com/{cs_service}/{version}/{cs_service}_{version}_SHA256SUMS'
            if ctx.obj['DEBUG'] is True:
                print_debug(f'Checksum URL: {checksum_url}')
        response = requests.get(checksum_url)
        if response.ok:
            checksums = response.text
            if ctx.obj['DEBUG'] is True:
                print_debug(f'Checksums:\n{checksums}')
        else:
            print_debug('Failed to download checksum file.')
            raise Exception('Failed to download checksum file.')
    filename = os.path.basename(file_path)
    expected_checksum = ""
    for line in checksums.splitlines():
        if filename in line:
            expected_checksum = line.split()[0]

    if not expected_checksum:
        print_debug(f'Checksum for {filename} not found in the checksum file.')
        raise Exception(f'Checksum for {filename} not found in the checksum file.')

    with open(file_path, 'rb') as f:
        file_data = f.read()
    calculated_checksum = hashlib.sha256(file_data).hexdigest()

    if calculated_checksum != expected_checksum:
        print_debug('Checksum does not match.')
        raise Exception('Checksum does not match.')
    else:
        print_debug('Checksum verified.')
        return True


# Extract and place the binary
def extract_and_place_binary(ctx, file_path, destination):
    if ctx.obj['DEBUG'] is True:
        print_debug('extract_and_place_binary entered', ctx.obj)
    if file_path.endswith('.zip'):
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(destination)
    elif file_path.endswith('.tar.gz'):
        with tarfile.open(file_path, 'r:gz') as tar_ref:
            tar_ref.extractall(destination)
    else:
        print_debug('Unsupported archive format')
        raise ValueError('Unsupported archive format')
    if ctx.obj['DEBUG'] is True:
        print_debug(f'Binary extracted and placed in {destination}')


def do_download(ctx):
    if ctx.obj['DEBUG'] is True:
        print_debug('do_download entered', ctx.obj)

    # Unpack the relevant context variables
    service = ctx.obj['dl_service']
    os_name = ctx.obj['dl_os']
    architecture = ctx.obj['dl_arch']
    consul_version = ctx.obj['dl_consul_version']
    vault_version = ctx.obj['dl_vault_version']
    consul_destination = ctx.obj['dl_consul_destination']
    vault_destination = ctx.obj['dl_vault_destination']

    url_consul_version = None
    url_vault_version = None

    ctx.obj['url_consul_version'] = url_consul_version
    ctx.obj['url_vault_version'] = url_vault_version

    # Construct the correct Consul URL
    if service == 'consul' or service == 'all':
        if consul_version == 'latest':
            _, url_consul_version = get_latest_version(ctx, 'consul')
        else:
            url_consul_version = consul_version
    ctx.obj['url_consul_version'] = url_consul_version
    if ctx.obj['DEBUG'] is True:
        print_debug(f'Consul version: {url_consul_version}')
        print_debug(f'Consul context version: {ctx.obj["url_consul_version"]}')
    consul_url, _ = construct_download_url(ctx)
    if consul_url not in [None, '']:
        downloaded_file = download_binary(ctx, consul_url, consul_destination)
        validate_checksum(ctx, 'consul', downloaded_file, url_consul_version)
        extract_and_place_binary(ctx, downloaded_file, ctx.obj['dl_consul_destination'])

    # Construct the correct Vault URL
    if service == 'vault' or service == 'all':
        if vault_version == 'latest':
            url_vault_version, _ = get_latest_version(ctx, 'vault')
        else:
            url_vault_version = vault_version
    ctx.obj['url_vault_version'] = url_vault_version
    if ctx.obj['DEBUG'] is True:
        print_debug(f'Vault version: {url_vault_version}')
        print_debug(f'Vault context version: {ctx.obj["url_vault_version"]}')
    _, vault_url = construct_download_url(ctx)
    if vault_url not in [None, '']:
        downloaded_file = download_binary(ctx, vault_url, vault_destination)
        validate_checksum(ctx, 'vault', downloaded_file, url_vault_version)
        extract_and_place_binary(ctx, downloaded_file, ctx.obj['dl_vault_destination'])

    # downloaded_file = download_vault(url, destination)
    # print(f'Verifying checksum for {downloaded_file}...')
    # if validate_checksum(downloaded_file, version):
    #     print('Checksum verified!')
    #     print(f'Extracting {downloaded_file}...')
    #     extract_and_place_binary(downloaded_file, destination)
    #     print('Vault binary is ready to use!')
    # else:
    #     print('Error: Checksum verification failed!')


# Base click group for the CLI
@click.group()
@click.pass_context
@click.option('--debug', is_flag=True, envvar='GRING_DEBUG', help='Will produce verbose output to screen for all steps.')
@click.option('--log', is_flag=True, envvar='GRING_LOG', help='If true, write verbose output to a logfile.')
@click.option('--log-dir', type=click.Path(), envvar='GRING_LOGDIR', help='Directory to write the logfile to.')
@click.option('--quiet', is_flag=True, envvar='GRING_QUIET', help='Do not output anything to the screen.')
def cli(ctx, debug, log, log_dir, quiet):
    """Gringott: A CLI Consul and Vault deployer.

    \f
    :param ctx: Click context
    :param debug: Debug option
    :param log: Log to file option
    :param log_dir: Log directory
    :param quiet: Quiet option
    """
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug
    ctx.obj['quiet'] = quiet
    setup_logging(log, debug, log_dir)
    if ctx.obj['DEBUG'] is True:
        print_debug('Debugging enabled.')


@cli.command()
@click.pass_context
@click.option('--service', 'service', type=click.Choice(['consul', 'vault', 'all']), default='all', required=True, envvar='GRING_DL_SERVICE', help='Which service to download')
@click.option('--os', 'os_name', required=True, envvar='GRING_DL_OS', help='Operating system')
@click.option('--arch', 'architecture', required=True, envvar='GRING_DL_ARCH', help='CPU architecture')
@click.option('--consul-version', 'consul_version', default='latest', envvar='GRING_DL_CONSUL_VERSION', help='Consul Version')
@click.option('--vault-version', 'vault_version', default='latest', envvar='GRING_DL_VAULT_VERSION', help='Vault Version')
@click.option('--consul-destination', 'consul_destination', default='.', envvar='GRING_DL_CONSUL_DEST', help='Destination directory for Consul binary')
@click.option('--vault-destination', 'vault_destination', default='.', envvar='GRING_DL_VAULT_DEST', help='Destination directory for Vault binary')
def download(ctx, service, os_name, architecture, consul_version, vault_version, consul_destination, vault_destination):
    """Command to download the Consul and/or Vault binary.

    \f
    :param ctx: Click context
    :param service: Which service to download
    :param os_name: Operating system
    :param architecture: CPU architecture
    :param consul_version: Consul version
    :param vault_version: Vault version
    :param consul_destination: Destination directory for Consul binary
    :param vault_destination: Destination directory for Vault binary
    """
    print_debug('download command called...')
    ctx.obj['dl_service'] = service
    ctx.obj['dl_os'] = os_name
    ctx.obj['dl_arch'] = architecture
    ctx.obj['dl_consul_version'] = consul_version
    ctx.obj['dl_vault_version'] = vault_version
    ctx.obj['dl_consul_destination'] = consul_destination
    ctx.obj['dl_vault_destination'] = vault_destination
    do_download(ctx)
    # Set either the requested version, or work out what the latest version is



if __name__ == '__main__':
    cli(max_content_width=120, obj={})

