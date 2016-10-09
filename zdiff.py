import sys

f1 = set()
f2 = set()

for l in open(sys.argv[1]):
    f1.add(l.rstrip())

for l in open(sys.argv[2]):
    f2.add(l.rstrip())

print "##", sys.argv[1], "Only"
for l in f1 - f2:
    print l

print "##", sys.argv[2], "Only"
for l in f2 - f1:
    print l

