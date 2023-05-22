import multiprocessing
import subprocess


def run_script(process_id):
    prefix = f"Process {process_id}: "
    # Replace "your_script.py" with your actual script name
    cmd = ["python3", "test.py"]
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    # Read and print the output with the prefix
    for line in process.stdout:
        print(prefix + line.strip())

    # Read and print the error messages with the prefix
    for line in process.stderr:
        print(prefix + line.strip())


if __name__ == "__main__":
    num_processes = 20  # Number of processes to run

    processes = []
    for i in range(num_processes):
        p = multiprocessing.Process(target=run_script, args=(i,))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()
