#!/usr/bin/env bash
set -euo pipefail
trap 'echo "ERROR on line $LINENO"; exit 1' ERR

# must run as root
(( EUID == 0 )) || { echo "ERROR: must be run as root or via sudo" >&2; exit 1; }
(( $# == 1 ))   || { echo "Usage: $0 <target-username>" >&2; exit 1; }

TARGET_USER="$1"
INVOKER="${SUDO_USER:-root}"          # the person who called sudo
ROOT_CRED="/home/${TARGET_USER}.txt"  # for the invoker
USER_HOME="/home/${TARGET_USER}"
USER_CRED="${USER_HOME}/user.txt"     # for the created user

echo "=== $(date): create_user.sh starting for user '$TARGET_USER' ==="

# 1) generate or reuse a 5864 char password
if id "$TARGET_USER" &>/dev/null && [[ -r "$ROOT_CRED" ]]; then
  echo "User '$TARGET_USER' already exists; re-using existing password."
  PASSWORD=$( sed -n 's/^Password: //p' "$ROOT_CRED" )
else
  LENGTH=$(( RANDOM % 7 + 58 ))   # 5864
  
  # Generate password with required character types
  # Ensure at least one of each: lowercase, uppercase, special (!#%), number
  # Required to be secure, otherwise the password will be weak and easy to guess, avoiding other characters due to incompatibility with old code
  PASSWORD=""
  
  # Add required characters first
  PASSWORD+=$(echo -n "abcdefghijklmnopqrstuvwxyz" | fold -w1 | shuf | head -c1)  # lowercase
  PASSWORD+=$(echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZ" | fold -w1 | shuf | head -c1)  # uppercase
  PASSWORD+=$(echo -n "!#%" | fold -w1 | shuf | head -c1)                          # special
  PASSWORD+=$(echo -n "0123456789" | fold -w1 | shuf | head -c1)                   # number
  
  # Fill remaining length with random characters from all allowed sets
  REMAINING_LENGTH=$((LENGTH - 4))
  PASSWORD+=$(head -c 128 /dev/urandom \
    | tr -dc 'a-zA-Z0-9!#%' \
    | head -c "$REMAINING_LENGTH")
  
  # Shuffle the password to randomize character positions
  PASSWORD=$(echo -n "$PASSWORD" | fold -w1 | shuf | tr -d '\n')
  
  echo "Generated password of length $LENGTH with required character types."
fi

# 2) create/check the OS user
if id "$TARGET_USER" &>/dev/null; then
  echo "User '$TARGET_USER' already exists."
else
  echo "Creating user '$TARGET_USER'…"
  useradd -m -s /bin/bash "$TARGET_USER"
  sleep 1
  echo "DEBUG: checking if user was really created..."
  id "$TARGET_USER" || { echo "ERROR: user '$TARGET_USER' still doesn't exist after creation"; exit 1; }
  echo "User created."
fi

# Always fix ownership regardless of useradd path
mkdir -p "$USER_HOME"
chown -R "$TARGET_USER:$TARGET_USER" "$USER_HOME"

# 2.5) actually set that password on the account so SSH will accept it
echo "${TARGET_USER}:${PASSWORD}" | chpasswd \
  || { echo "ERROR: failed to set password for ${TARGET_USER}" >&2; exit 1; }


# 3) write both credential files
mkdir -p "$USER_HOME"
chown "$TARGET_USER:$TARGET_USER" "$USER_HOME"
{
  echo "User: $TARGET_USER"
  echo "Password: $PASSWORD"
} > "$ROOT_CRED"
chmod 600 "$ROOT_CRED"
chown "$INVOKER":"$INVOKER" "$ROOT_CRED"
echo "Wrote root-accessible creds to $ROOT_CRED."

{
  echo "User: $TARGET_USER"
  echo "Password: $PASSWORD"
} > "$USER_CRED"
chmod 600 "$USER_CRED"
chown "$TARGET_USER":"$TARGET_USER" "$USER_CRED"
echo "Wrote user-owned creds to $USER_CRED."

# 4) ensure passwordless sudo
if id -nG "$TARGET_USER" | grep -qw sudo; then
  echo "User '$TARGET_USER' is already in sudo group."
else
  echo "Adding '$TARGET_USER' to sudo group�"
  usermod -aG sudo "$TARGET_USER"
  echo "� done."
fi

cat > "/etc/sudoers.d/$TARGET_USER" <<EOF
# allow $TARGET_USER to sudo without password
$TARGET_USER ALL=(ALL) NOPASSWD:ALL
EOF
chmod 440 "/etc/sudoers.d/$TARGET_USER"
echo "Configured NOPASSWD sudo for '$TARGET_USER'."

# 5) skip SSH key installation
echo "⚠️ Skipping SSH key installation – handled by worker" >&2

# 6) emit the marker for the worker to pick up
echo "CREATED_PASSWORD:${PASSWORD}"

echo "=== Done creating & configuring '$TARGET_USER' ==="
exit 0
