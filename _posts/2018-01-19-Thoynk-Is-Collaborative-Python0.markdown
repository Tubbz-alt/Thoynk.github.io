---
layout: post
title:  "Thoynk Is Collaborative Python ... and other things!"
date:   2018-01-19 12:41:30 -0600
categories: Thoynk update
---
This is a trial run of Jekyll ... for a lot of different reasons, maybe because Jekyll offers powerful support for code snippets such as the Towers of Hanoi code from [Python Course](https://www.python-course.eu/python3_course.php):

{% highlight python %}
#=> just an example to show highlighting functionality ...
def hanoi(n, source, helper, target):
    if n > 0:
        # move tower of size n - 1 to helper:
        hanoi(n - 1, source, target, helper)
        # move disk from source peg to target peg
        if source:
            target.append(source.pop())
        # move tower of size n-1 from helper to target
        hanoi(n - 1, helper, source, target)

source = [4,3,2,1]
target = []
helper = []
hanoi(len(source),source,helper,target)

print source, helper, target
#=> just an example to show highlighting functionality ...
{% endhighlight %}

But maybe we can actually add something like [Datacamp Light][datacamp-light] to Jekyll?

Will need to read the [Jekyll docs][jekyll-docs] and the [Jekyll’s GitHub repo][jekyll-gh] ... maybe ask some questions at [Jekyll Talk][jekyll-talk].

[jekyll-docs]:    https://jekyllrb.com/docs/home
[jekyll-gh]:      https://github.com/jekyll/jekyll
[jekyll-talk]:    https://talk.jekyllrb.com/
[datacamp-light]: https://github.com/datacamp/datacamp-light
