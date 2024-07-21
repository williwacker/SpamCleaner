import os, sys, re

VERSION_REGEX = r'v?[0-9]+\.[0-9]+\.[0-9]+'

def isValidTag(tag):
	if tag is None:
		return False
	if tag == '':
		return False

	regex = re.compile(VERSION_REGEX)
	if regex.match(tag):
		return True

	print('WARNING: Ignoring invalid tag: {}'.format(tag))
	return False

def versionTuple(v):
	has_version_prefix = v.find('v') >= 0
	components = v.replace('v', '').split('.')
	if not isValidTag(v):
		raise ValueError('Invalid version detected: ' + v)

	version = tuple(map(int, components))
	return (version, has_version_prefix)

def versionTupleToString(v, append_version_prefix):
	return '{}{}.{}.{}'.format('v' if append_version_prefix else '', v[0], v[1], v[2])

def scanCurrentBranchTagsAndGetBiggestVersion():
	log_for_current_branch = os.popen('git log --decorate --pretty=oneline').read()
	all_tags = []
	log_tag_version_regex = r'tag: ({})'.format(VERSION_REGEX)
	for line in log_for_current_branch.split('\n'):
		for match in re.finditer(log_tag_version_regex, line):
			all_tags.append(match.group(1))

	biggest_tag_version = ()
	for tag in all_tags:
		if isValidTag(tag):
			tag_version = versionTuple(tag)
			if len(biggest_tag_version) == 0 or biggest_tag_version[0] < tag_version[0]:
				biggest_tag_version = tag_version
	return biggest_tag_version

def getBiggestVersionTagForCurrentBranch():
	last_tag = os.popen('git describe --abbrev=0 --tags').read().replace('\n', '')
	if not isValidTag(last_tag):
		raise ValueError('Cannot read the last tag version. Please use a valid tag format (v1.2.3 or 1.2.3) for the last tagged commit in current branch')

	current_version = versionTuple(last_tag)
	biggest_version_for_branch = scanCurrentBranchTagsAndGetBiggestVersion()
	if len(biggest_version_for_branch) == 0:
		raise ValueError('Cannot read any tag from current branch.')

	if current_version[0] != biggest_version_for_branch[0]:
		print('WARNING: The latest tag ({}) is not the biggest version in branch ({}). Using biggest version.'.format(last_tag, versionTupleToString(biggest_version_for_branch[0], has_version_prefix[1])))

	return biggest_version_for_branch

def createNewTagOnCurrentHeadIfNotTagged(current_tag, new_tag):
	tag_in_head = os.popen('git tag --contains HEAD').read().replace('\n', '')
	if tag_in_head != '':
		print('No new tag. HEAD already tagged as {}'.format(tag_in_head))
	else:
		print('Creating new tag: {} (previous tag for branch: {})'.format(new_tag, current_tag))
		os.popen('git tag {} HEAD'.format(new_tag))

def composeCandidateTagFromArguments(current_tag):
	tag = None
	if len(sys.argv) > 1 and sys.argv[1] == 'bump-minor':
		tag = (current_tag[0], current_tag[1] + 1, 0)
	elif len(sys.argv) > 1 and sys.argv[1] == 'bump-major':
		tag = (current_tag[0] + 1, 0, 0)
	else:
		tag = (current_tag[0], current_tag[1], current_tag[2] + 1)
	return tag

#run!
current_tag = getBiggestVersionTagForCurrentBranch()
has_version_prefix = current_tag[1]
new_version_tag = composeCandidateTagFromArguments(current_tag[0])
createNewTagOnCurrentHeadIfNotTagged(versionTupleToString(current_tag[0], has_version_prefix), versionTupleToString(new_version_tag, has_version_prefix))
