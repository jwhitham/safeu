#!/usr/bin/python
# SSH Agent File Encryption Utility (safeu)
# Copyright (C) Jack Whitham 2016-2017
# 
# https://github.com/jwhitham/safeu/
# https://www.jwhitham.org/
# 
# ex: set tabstop=4 noexpandtab shiftwidth=4:
#

import subprocess, os, sys, signal, hashlib

PROGRAM = "safeu"
LAUNCH = "../" + PROGRAM
LIBTEST = "libtest"
SSH_AUTH_SOCK = "SSH_AUTH_SOCK"
SSH_AGENT_PID = "SSH_AGENT_PID"
SOCKET_DIR = "ssh-test1234"
OVERRIDE_ADDRESS = SOCKET_DIR + "/agent.1234" 
agent_socket = agent_pid = None
rsa_fp = dsa_fp = None

def clear_sas():
	try:
		del os.environ[SSH_AUTH_SOCK]
	except:
		pass

def cleanup():
	global agent_pid
	clear_sas()

	for tf in ["coverage.txt",
			"x", "y", "y1", "z", "test1.tmp", "test2.tmp", "test3.tmp",
			"rsa", "dsa", "rsa.pub", "dsa.pub", OVERRIDE_ADDRESS]:
		try:
			os.unlink(tf)
		except:
			pass
	try:
		os.rmdir(SOCKET_DIR)
	except:
		pass

	if agent_pid != None:
		os.kill(agent_pid, signal.SIGTERM)
		agent_pid = None

def make():
	subprocess.check_call(["make", "-C", "..", "clean", PROGRAM, "tests/" + LIBTEST])

def start_agent():
	global agent_pid
	global agent_socket
	print ("Start an agent for test purposes")
	agent = subprocess.Popen(["ssh-agent", "-a", OVERRIDE_ADDRESS], stdout = subprocess.PIPE)
	(stdout, stderr) = agent.communicate()
	agent.wait()

	# example: "SSH_AUTH_SOCK=/tmp/ssh-aAEL7IazBOnc/agent.1768; export SSH_AUTH_SOCK; ..."
	i = stdout.find(SSH_AUTH_SOCK + "=")
	assert i >= 0, "agent output did not contain " + SSH_AUTH_SOCK + "="
	j = stdout.find(";", i)
	assert j > 0, "agent output did not include ';'"
	agent_socket = stdout[i + len(SSH_AUTH_SOCK) + 1 : j]
	assert agent_socket.find(OVERRIDE_ADDRESS) >= 0, "expected a specific socket name"
	assert os.path.exists(agent_socket), "agent output did not include a recognisable socket name"
	print ("Agent: " + SSH_AUTH_SOCK + "=" + agent_socket)
	os.environ[SSH_AUTH_SOCK] = agent_socket

	i = stdout.find(SSH_AGENT_PID + "=", j)
	assert i > 0, "agent output did not contain " + SSH_AGENT_PID + "="
	j = stdout.find(";", i)
	assert j > 0, "agent output did not include ';'"
	agent_pid = int(stdout[i + len(SSH_AGENT_PID) + 1 : j])
	assert agent_pid >= 0
	print ("Agent PID: " + str(agent_pid))

def test_run(args, expected_either = None, expected_stdout = None, expected_stderr = None,
					expected_rc = 1, program = None):
	print ("")
	print ("")
	print ("")
	print ("Test case: %s" % args)
	if program == None:
		program = LAUNCH
	if os.path.isfile(program):
		program = "./" + program
	p = subprocess.Popen([program] + args, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
	(stdout, stderr) = p.communicate()
	rc = p.wait()

	print ("stdout = %s" % stdout.strip())
	print ("stderr = %s" % stderr.strip())
	print ("rc = %d" % rc)
	print ("expected_either = %s" % expected_either)
	print ("expected_stdout = %s" % expected_stdout)
	print ("expected_stderr = %s" % expected_stderr)
	print ("expected_rc = %d" % expected_rc)

	if expected_either != None:
		assert (stdout + stderr).find(expected_either) >= 0, "test failed, text not matched: " + expected_either

	if expected_stdout != None:
		assert stdout.find(expected_stdout) >= 0, "test failed, stdout not matched: " + expected_stdout

	if expected_stderr != None:
		assert stderr.find(expected_stderr) >= 0, "test failed, stderr not matched: " + expected_stderr

	assert expected_rc == rc, "test failed, rc not matched: " + str(expected_rc)

	print ("Test case passed")
	return stdout

def agentless_tests():
	test_run([], "no operation was specified")
	test_run(["--help"], "--help requested")
	test_run(["-h"], "--help requested")

	test_run([], "unable to find an SSH agent", expected_rc = 1, program = LIBTEST)

def keyless_tests():
	test_run(["--encrypt", "x"], "--output is required")
	test_run(["--decrypt", "x"], "--output is required")

	test_run(["--encrypt", "x", "--output", "y"], "agent does not hold any keys")

	test_run(["--list"], "agent does not hold any keys", expected_rc = 1)

	test_run([], "decryption key is not present in the agent", expected_rc = 1, program = LIBTEST)

def create_key(name_and_type):
	print ("Create key: %s" % name_and_type)
	comment = "test " + name_and_type + " key"
	p = subprocess.Popen(["ssh-keygen", "-f", name_and_type, "-t", name_and_type,
						"-b", "1024", "-P", "",
						"-C", comment],
						stdout = subprocess.PIPE)
	(stdout, _) = p.communicate()
	rc = p.wait()

	print ("stdout = %s" % stdout.strip())
	print ("rc = %d" % rc)
	assert rc == 0
	fingerprint = None

	for line in stdout.split("\n"):
		if line.find(comment) >= 0:
			fingerprint = line[:10]

	print ("fingerprint = %s" % fingerprint)
	assert fingerprint != None

	subprocess.check_call(["ssh-add", name_and_type])
	return fingerprint

def test_decrypt(fcontents, args):
	test_run(["--decrypt", "y", "--output", "z"] + args, expected_rc = 0)
	assert open("z", "rb").read() == fcontents

def load_ref_key():
	# refkey is a normal OpenSSH key file, but every byte has been xored with 0xff to
	# prevent online hosting services detecting that it is a private key and refusing
	# to allow it to be checked in
	open("x", "wb").write(''.join([ chr(ord(b) ^ 0xff) for b in open("refkey").read() ]))
	try:
		os.chmod("x", 0600)
	except:
		pass
	subprocess.check_call(["ssh-add", "x"])

def agent_tests():
	test_run(["--list"], rsa_fp, expected_rc = 0)
	test_run(["--decrypt", "y", "--output", "z"], "unable to open input file")

	for fcontents in ["", "T", "TESTING MORE STUFF"]:
		# Encrypt test file
		open("x", "wb").write(fcontents)
		test_run(["--encrypt", "x", "--output", "y"], expected_rc = 0)
		assert len(open("y", "rb").read()) >= (48 + len(fcontents)) # 48 is header size for empty file

		# Decrypt test file
		test_decrypt(fcontents, [])

	test_run(["--decrypt", "y", "--output", "/"], "Is a directory")

	# environment cleared, to test --socket and --search
	clear_sas()
	test_run(["--decrypt", "y", "--output", "z"], "agent may not be available")
	test_decrypt(fcontents, ["--socket", agent_socket])
	test_decrypt(fcontents, ["--search"])
	os.environ[SSH_AUTH_SOCK] = agent_socket

	# Load reference key and decrypt reference file, checking for a word in the secret message
	load_ref_key()
	test_run(["--decrypt", "cipher1a", "--output", "z"], expected_rc = 0)
	b = open("z", "rb").read().find("Butterfly")
	assert b == 216, "Secret message is incorrect"

	# Same test with larger file
	test_run(["--decrypt", "cipher1b", "--output", "z"], expected_rc = 0)
	b = hashlib.md5(open("z", "rb").read()).hexdigest()
	assert b == "3a7145d48ff55e095a62d9edf3cb8e37", "cipher1b did not decode correctly"

	# Same test with version 2 file
	test_run(["--decrypt", "cipher2a", "--output", "z"], expected_rc = 0)
	b = hashlib.md5(open("z", "rb").read()).hexdigest()
	assert b == "eb857e2dda7c42e55dedd09df69f96fe", "cipher2a did not decode correctly"

	# Don't have the keys for this one
	test_run(["--decrypt", "cipher2b", "--output", "z"], expected_rc = 1,
				expected_stderr = "decryption key is not present in the agent")

	# check password decryption code
	test_run([], "libtest ok", expected_rc = 0, program = LIBTEST)

	# built-in self test
	test_run(["--test-safeu"], "test passed", expected_rc = 0)


def main():
	global rsa_fp, dsa_fp
	os.environ["TMPDIR"] = os.environ["TMP"] = os.getcwd()
	os.mkdir(SOCKET_DIR)
	make()
	agentless_tests()
	start_agent()
	keyless_tests()
	dsa_fp = create_key("dsa")
	keyless_tests()
	rsa_fp = create_key("rsa")
	agent_tests()

	print ("All test cases passed")

if "--instr" in sys.argv:
	PROGRAM = "instr_safeu"
	LAUNCH = "../instr_safeu"

try:
	cleanup()
	main()
	if "--instr" in sys.argv:
		subprocess.check_call(["make", "-C", "..", "tests/report.txt"])
		
finally:
	cleanup()


