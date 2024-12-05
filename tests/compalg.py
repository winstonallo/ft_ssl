import subprocess
import sys

def run_command(command):
    """Run a command and return the output."""
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise Exception(f"Command failed: {command}\nError: {result.stderr}")
    return result.stdout.strip()

def check_hash(algo, file_path):
    """Check the hash of the file using ft_ssl and the system's hash."""
    
    ft_ssl_command = ["./ft_ssl", algo, "-q", file_path]
    try:
        ft_ssl_output = run_command(ft_ssl_command)
    except Exception as e:
        print(f"Error running ft_ssl: {e}")
        return

    sum_command = [algo + "sum", file_path]
    try:
        sum_output = run_command(sum_command)
    except Exception as e:
        print(f"Error running {algo}sum: {e}")
        return
    
    ft_ssl_hash = ft_ssl_output.split(" ")[0]
    sum_hash = sum_output.split(" ")[0]

    if ft_ssl_hash == sum_hash:
        print(f"SUCCESS: {algo.upper()} hash matches.")
        print(f"ft_ssl hash:\t{ft_ssl_hash}")
        print(f"{algo}sum hash:\t{sum_hash}")
    else:
        print(f"FAILURE: {algo.upper()} hash does not match.")
        print(f"ft_ssl hash:\t{ft_ssl_hash}")
        print(f"{algo}sum hash:\t{sum_hash}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 check_hash.py <algorithm> <file_path>")
        sys.exit(1)
    
    algorithm = sys.argv[1]
    file_path = sys.argv[2]

    if algorithm not in ["md5", "sha256", "sha512", "sha224", "sha384"]:
        print("Unsupported algorithm. Supported algorithms: md5, sha256, sha512, sha224, sha384")
        sys.exit(1)

    check_hash(algorithm, file_path)
