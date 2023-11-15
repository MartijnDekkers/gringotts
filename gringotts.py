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
    logger.debug(f'DEBUG: {caller.filename}:{caller.lineno}, {caller.function}:\nDEBUG: {msg}, {args}')


# Base click group for the CLI
@click.group()
@click.option('--debug', is_flag=True, envvar='GRING_DEBUG', help='Will produce verbose output to screen for all steps.')
@click.option('--log', is_flag=True, envvar='GRING_LOG', help='If true, write verbose output to a logfile.')
@click.option('--log-dir', type=click.Path(), envvar='GRING_LOGDIR', help='Directory to write the logfile to.')
@click.option('--quiet', is_flag=True, envvar='GRING_QUIET', help='Do not output anything to the screen.')
@click.pass_context
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
    setup_logging(log, debug, log_dir)
    if ctx.obj['DEBUG'] is True:
        print_debug('Debugging enabled.')


@cli.command()
@click.option('--service', 'service', type=click.Choice(['consul', 'vault', 'all']), default='all', required=True, envvar='GRING_DL_SERVICE', help='Which service to download')
@click.option('--os', 'os_name', required=True, envvar='GRING_DL_OS', help='Operating system')
@click.option('--arch', 'architecture', required=True, envvar='GRING_DL_ARCH', help='CPU architecture')
@click.option('--consul-version', 'consul_version', default='latest', envvar='GRING_DL_CONSUL_VERSION', help='Consul Version')
@click.option('--vault-version', 'vault_version', default='latest', envvar='GRING_DL_VAULT_VERSION', help='Vault Version')
@click.option('--consul-destination', 'consul_destination', default='.', envvar='GRING_DL_CONSUL_DEST', help='Destination directory for Consul binary')
@click.option('--vault-destination', 'vault_destination', default='.', envvar='GRING_DL_VAULT_DEST', help='Destination directory for Vault binary')
@click.pass_context
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
    # Set either the requested version, or work out what the latest version is
    # if version == 'latest':
    #     version = get_latest_version()
    #
    # url = construct_download_url(os_name, architecture, version)
    # print(f'Downloading Vault v{version} for {os_name}/{architecture}...')
    # downloaded_file = download_vault(url, destination)
    # print(f'Verifying checksum for {downloaded_file}...')
    # if validate_checksum(downloaded_file, version):
    #     print('Checksum verified!')
    #     print(f'Extracting {downloaded_file}...')
    #     extract_and_place_binary(downloaded_file, destination)
    #     print('Vault binary is ready to use!')
    # else:
    #     print('Error: Checksum verification failed!')


if __name__ == '__main__':
    cli(max_content_width=120, obj={})

