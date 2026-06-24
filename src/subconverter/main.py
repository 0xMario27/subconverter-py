"""subconverter-py - Main entry point.

A Python port of subconverter utility to convert between various proxy subscription formats.
"""

import os
import sys
import signal
import argparse

from .config.settings import global_settings
from .config.loader import read_conf, refresh_rulesets
from .utils.logger import write_log, LOG_LEVEL_INFO
from .utils.network import set_global_settings

VERSION = "0.1.0"


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=f"subconverter-py v{VERSION} - Proxy subscription format converter"
    )
    parser.add_argument('-f', '--file', type=str, default=None,
                       help='Path to configuration file')
    parser.add_argument('-l', '--log', type=str, default=None,
                       help='Log output file')
    parser.add_argument('--host', type=str, default=None,
                       help='Listen address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=None,
                       help='Listen port (default: 25500)')
    parser.add_argument('-g', '--gen', action='store_true',
                       help='Generator mode')
    parser.add_argument('--artifact', type=str, default=None,
                       help='Generate profiles artifact')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode')

    args = parser.parse_args()

    # Set up CD (change directory) to script location
    try:
        exe_path = os.path.realpath(sys.argv[0])
        os.chdir(os.path.dirname(exe_path))
    except Exception:
        pass

    # Find preference file
    pref_path = args.file
    if not pref_path:
        for name in ["pref.toml", "pref.yml", "pref.ini"]:
            if os.path.isfile(name):
                pref_path = name
                break

    if not pref_path:
        # Try to create from example
        for src, dst in [
            ("pref.example.toml", "pref.toml"),
            ("pref.example.yml", "pref.yml"),
            ("pref.example.ini", "pref.ini"),
        ]:
            if os.path.isfile(src):
                import shutil
                shutil.copy2(src, dst)
                pref_path = dst
                break

    if pref_path:
        global_settings.pref_path = pref_path
        # CD to pref path directory
        pref_dir = os.path.dirname(pref_path)
        if pref_dir:
            os.chdir(pref_dir)
            global_settings.pref_path = os.path.basename(pref_path)
    else:
        global_settings.pref_path = "pref.ini"

    # Read environment variables
    env_api_mode = os.environ.get('API_MODE', '')
    env_managed_prefix = os.environ.get('MANAGED_PREFIX', '')
    env_token = os.environ.get('API_TOKEN', '')
    env_port = os.environ.get('PORT', '')

    if env_api_mode:
        global_settings.api_mode = env_api_mode.lower() != 'false'
    if env_managed_prefix:
        global_settings.managed_config_prefix = env_managed_prefix
    if env_token:
        global_settings.access_token = env_token
    if env_port:
        try:
            global_settings.listen_port = int(env_port)
        except ValueError:
            pass

    # Command line overrides
    if args.host:
        global_settings.listen_address = args.host
    if args.port:
        global_settings.listen_port = args.port

    # Update connection settings to bind all interfaces
    global_settings.listen_address = args.host or global_settings.listen_address

    write_log(0, f"SubConverter v{VERSION} starting up..", LOG_LEVEL_INFO)

    # Read configuration
    try:
        read_conf(global_settings.pref_path)
    except Exception as e:
        write_log(0, f"Warning: Could not read config: {e}", LOG_LEVEL_INFO)

    # Refresh rulesets
    if not global_settings.update_ruleset_on_request:
        refresh_rulesets(global_settings.custom_rulesets,
                        global_settings.rulesets_content)

    # Set global settings for network module
    set_global_settings(global_settings)

    # Generator mode
    if args.gen or global_settings.generator_mode:
        print("Generator mode: not yet implemented in Python version")
        return 0

    # Start web server
    from .handler.interfaces import create_app

    app = create_app()

    # Setup signal handlers
    def signal_handler(sig, frame):
        write_log(0, f"Interrupt signal {sig} received. Exiting gracefully...", LOG_LEVEL_INFO)
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    write_log(0, f"Startup completed. Serving HTTP @ http://{global_settings.listen_address}:{global_settings.listen_port}",
             LOG_LEVEL_INFO)

    # Print startup info
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"  subconverter-py v{VERSION}", file=sys.stderr)
    print(f"  Listening on: {global_settings.listen_address}:{global_settings.listen_port}", file=sys.stderr)
    print(f"  Pref file: {global_settings.pref_path}", file=sys.stderr)
    print(f"  API Mode: {'ON' if global_settings.api_mode else 'OFF'}", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)

    # Use waitress or gunicorn for production, Flask dev server for development
    try:
        use_debug = args.debug or os.environ.get('FLASK_ENV') == 'development'
        if use_debug:
            app.run(
                host='0.0.0.0',
                port=global_settings.listen_port,
                debug=True,
                use_reloader=False,
            )
        else:
            # Try to use waitress for production
            try:
                from waitress import serve
                serve(app, host='0.0.0.0', port=global_settings.listen_port)
            except ImportError:
                app.run(
                    host='0.0.0.0',
                    port=global_settings.listen_port,
                    debug=False,
                    use_reloader=False,
                )
    except KeyboardInterrupt:
        pass

    return 0


if __name__ == '__main__':
    sys.exit(main())
