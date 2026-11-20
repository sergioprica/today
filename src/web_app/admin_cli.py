"""CLI controlado de servidor para asignar o revocar el rol 'admin' (RF-05.1)."""

import argparse
import sys

import psycopg

from web_app import admin_service, config


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="manage-admin",
        description="Aprovisionamiento controlado de cuentas 'admin' en app_sec.users.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    promote_cmd = subparsers.add_parser(
        "promote", help="Asigna el rol 'admin' a una cuenta activa con 2FA."
    )
    promote_cmd.add_argument("--email", required=True, help="Correo del usuario.")

    demote_cmd = subparsers.add_parser(
        "demote", help="Revoca el rol 'admin' devolviendo la cuenta a 'user'."
    )
    demote_cmd.add_argument("--email", required=True, help="Correo del usuario.")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "promote":
            uid = admin_service.promote_user_to_admin(args.email)
            print(f"Rol 'admin' asignado a {args.email.strip().lower()} ({uid})")
        elif args.command == "demote":
            uid = admin_service.demote_admin_to_user(args.email)
            print(f"Rol 'user' asignado a {args.email.strip().lower()} ({uid})")
    except (config.ConfigError, LookupError, ValueError, psycopg.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
