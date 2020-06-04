---
layout:     post
title:      "关于Java Memory Model"
date:       2020-06-04
author:     "withparadox2"
catalog: true
tags:
  - java
mathjax: true  
---

在这篇文章中我只打算讲一下[Causality Requirements for Executions](https://docs.oracle.com/javase/specs/jls/se7/html/jls-17.html#jls-17.4.8)所提到的9条规则中的三条(5、6、7)，这也是规范中不太容易理解的地方。当然，在此之前我会介绍一下与之相关的背景。我并不能保证这里所有的论述都是正确无误的，所以大家在阅读时如若发现问题还请指出。

## 1 背景
Java内存模型是由基本模型演化过来的，主要经历三个模型。

### 1.1 Sequential Consistency Memory Model
首先考虑的是Sequential Consistency Memory Model，它规定所有线程中的action需要按照一个total order来执行(每次执行时这个total order可以不一致)，对于在单个线程中所执行的action，其顺序必须和代码中规定的顺序(program order)一致，并且每一步执行对所有线程来说都是可见的。这个模型太过强硬，要求和program order一致，如果使用这个模型，那么很多优化就做不了了，比如指令重排序以及读写缓存等。因此，需要找到一个稍微弱一点的模型。

### 1.2 Happens-Before Memory Model
接下来考虑的是Happens-Before Memory Model，这个模型规定了一系列happen-before关系，下面列出其中的一部分：

- 如果x和y在同一个线程，并且在program order下x在y之前，那么x happen-before y
- 一个volatile变量的写action happen-before后续对该变量的读action
- 如果x happen-before y，并且y happen-before z，那么x happen-before z
- ……

规范指出如果第一个action happen-before第二个，那么第一个action必须对第二个可见且排在第二个之前。看上面列出的第一条happen-before关系，这是不是意味着同一个线程内的指令无法重排了呢？当然不是，规范里面还提到一点来允许重排：

> It should be noted that the presence of a happens-before relationship between two actions does not necessarily imply that they have to take place in that order in an implementation. If the reordering produces results consistent with a legal execution, it is not illegal.

除了happen-before关系外，Happens-Before Memory Model还对一个读action(r)所能看见的写action(w)进行了规定：

- w happen-before r，并且不存在其他的写操作w’满足w happen-before w’并且w’ happen-before r
- w和r之间不存在happen-before关系

第一点还比较好理解，但是第二点又是讲了什么？在阐明之前先引入一个称作data race的概念，在对同一个共享变量所执行的action(读或写)中，如果两个action之间没有happen-before关系，且至少有一个为写action，那么称这两个action之间存在data race。下面看看去掉第二点就会导致什么，假设有两个线程，一个线程有一个对变量的写action，另一个线程有一个对相同变量的读action，这两个线程之间没有做任何同步，也就是说这两个action之间不存在happen-before关系。只根据第一点，那么这里所提到的读action将永远看不见写action，这是不符合常理的，而引入第二点则允许data race的发生。

关于这两点，举个例子说明下：

```
init:a = 0, b = 0

Thread1        | Thread2
---------------|----------
1, r1 = a      | 3, r2 = b
2, b = 1       | 4, a = 2
```

列出有效的happen-before关系如下，将a happen-before b记为hb(a, b)：

```
hb(a  = 0, r1 = a)
hb(r1 = a, b  = 1)
hb(b  = 0, r2 = b)
hb(r2 = b, a  = 2)
```

根据第一条规则，r2 = b可以看见0，r1 = a可以看见0；根据第二条规则，r2 = b可以看见1，r1 = a可以看见2。也就是说，对于这段代码，下面四种结果在该内存模型下都是允许的：

```
(a) r1 = 0; r2 = 0
(b) r1 = 2; r2 = 0
(c) r1 = 0; r2 = 1
(d) r1 = 2; r2 = 1
```

得到其他结果比较简单，对于结果d，我们看看如何执行才能得到它。编译器在分析Thread1时会发现1和2之间并没有相关，所以可以因为某些原因将b = 1提前，执行过2后在Thread2中执行3，接着执行4，最后由Thread1执行1，这样就得到了结果d。

到目前来看，Happens-Before Memory Model没有什么问题，但事实上它是有缺陷的。我们将上面的例子修改如下：

```
init:a = 0, b = 0

Thread1        | Thread2
---------------|----------
r1 = a         | r2 = b
if(r1 != 0)    | if(r2 != 0)
   b = 1       |   a = 2
```

此时唯一正确的结果是r1 = 0; r2 = 0。但是在Happens-Before Memory Model下，r1 = 2; r2 = 1也是合法的，因为这里happen-before关系不变，r2 = b可以看见b = 1，这将导致a = 2的执行，然后得到r1 = a = 2，到此已经执行完了，当我们拿个r1 = 2这个结果时，后验的发现这确实将导致b = 1的执行，因此r2看见b = 1也就没问题了，这种循环推理被称作因果关系(causality)。看着都感觉有些荒唐，也就是说，抽象的模型已经无法适应现实的程序了，需要改进。

### 1.3 Java Memory Model
现在我们遇到的问题在于什么时候可以将一个写的位置提前，规范给出：

> An action can occur earlier in an execution than it appears in program order. However, that write must have been able to occur in the execution without assuming that any additional reads see values via a data race.

注：引用来自[1](http://www.cs.umd.edu/~pugh/java/memoryModel/Dagstuhl.pdf)

前面Happens-Before Memory Model中我们讲了一个读action可以看到的写action满足两个条件，一个是满足happen-before关系，另一个是不存在happen-before关系。而这里要求的是如果一个写action可以提前，那么它必须在仅仅看见与其满足happen-before关系的write条件下会发生，而无须考虑不存在happen-before关系的写action。还是看下前面的例子，在Happens-Before Memory Model中我们将b = 1提前了，由于Thread2中的a = 2与Thread1中的r1 = a存在data race关系，由此导出的r1 = 2即不满足上述条件，事实上b = 1所满足的happen-before关系如下：

```
hb(a = 0, r1 = a)
hb(b = 0, r1 = a)
hb(r1 = a, b = 1)
```

在这种happen-before的限制下，b = 1是无法执行的，因此它不能被提前。

至此，我们得到了Java Memory Model，Java Memory Model仅仅在Happens-Before Memory Model添加了对causality的限制。

另一个需要考虑的问题是，给出一段程序和一个输出结果，如何判断这个结果是否合法呢？思路是，找到所有的合法结果，看看给定的结果是否在其中。事实上，找到这些结果本身是不可能的，但不妨碍我们对简单的案例进行分析。整个过程分为两步：

第一步，列出所有待提交的action，首先提交初始条件里的action，然后根据上文提到的happen-before限制来递归的提交剩下的action，通过这种方式我们可以找到哪些action一定会发生，因而可以将其提前。

第二步，重新开始一个新的提交过程，列出所有待提交的action，首先提交上一步中收集的可以提前的action(由于提交的action是经过检验的action，因此后续提交的读action是可以看见它们)，然后递归提交剩下的action，全部提交完后便会得到一个结果，在提交过程中选择不同的提交顺序便会得到不同的结果。

下面通过一个例子(来自JMM规范制定小组所发布的一系列Test Cases，该例为Case-18)来简要讲一下流程：

```
init:x = y = 0

Thread1        | Thread2
---------------|----------
r3 = x         | r2 = y
if (r3 == 0)   | x = r2
  x = 42       |    
r1 = x         |   
y = r1         |    

output: r1 == r2 == r3 == 42
```

如果要得到r2 = 42，则需要将y = 42提前，那么能否这样做呢？编译器在对Thread1做intra-thread分析时会发现写入x的值要么为0要么为42，如果r3 != 0，那么必然有x = 42，如果r3 == 0，那么接下来就会执行x = 42，所以可以保证r1 = x看到的值为42，因此将其改为r1 = 42，将y = r1改为y = 42并提前。第二步中的提交过程如下：

列出所有待提交的action如下，括号里代表当前可以看到的值，这里省略了初始状态x = 0以及y = 0：

```
r3 = x  (0)
x  = 42
r1 = x  (42)
y  = r1 (42)	# to be committed
r2 = y  (0)
x  = r2
```
经过分析，y = 42可以提前，因此首先提交y = r1 (42)：

```
y  = r1 (42)    # committed
r3 = x  (0)
x  = 42
r1 = x  (42)	
r2 = y  (0)     # to be committed 可以看见y = r1(42)
x  = r2
```

起初r2 = y只能看见happen-before关系的write，也就是y = 0，提交y = r1(42)后，r2 = y现在也可以看见与它无happen-before关系的y = 42，为了得到结果，接下来就提交r2 = y:
```
y  = r1 (42)    
r2 = y  (42)    # committed
r3 = x  (0)
x  = 42
r1 = x  (42)	     
x  = r2 (42)    # to be committed
```
提交x = r2：
```
y  = r1 (42)    
r2 = y  (42)   
x  = r2         # committed
r3 = x  (0)     # to be committed， 可以看见x = r2(42) 
x  = 42
r1 = x  (42)	# to be committed， 可以看见x = r2(42)
```
把剩下的两个action提交了：
```
y  = r1 (42)    
r2 = y  (42)   
x  = r2 (42)    
r3 = x  (42)     # committed
r1 = x  (42)	 # committed
```
到此说明了给出的结果是合法的。

## 2 Rules
这里不打算列出其他规则，以及规范在上下文中所给出的各种形式化定义，只列出开头所提到的三条规则，然后对其进行分析。如果说前面的流程看明白了，那么这里应该是水到渠成，只是形式化的东西多少显得有些抽象。
- 5 `$W_i|C_{i-1}=W|C_{i-1}$`
- 6 For any read $r\in A_i-C_{i-1}$ we have $W_i(r)\stackrel{hb_i}{\longrightarrow} r$
- 7 For any read $r\in C_i-C_{i-1}$ we have $W_i(r)\in C_{i-1}$ and $W(r)\in C_{i-1}$

先看rule 6，这一条讲了对于当前正在提交的每一个读action(r)，它所能看到的写action(w)都必须满足w happen-before r。我们知道happen-before关系是偏序的，不会得到违反因果关系的结果，这一条已经满足了causality requirements。但是只有这一条还不够，它限制了data race的发生，这不是我们所希望的，这也是引入rule 7的原因。根据前面的描述，我们不能让这个读action看到所有与它有data race的写action，一个自然的想法是当这个读action被提交后，它可以看见于它先提交的写action(justified action)，因为既然写action已经提交了，说明会发生，那么这个读action可以看见它就是正常的事情。这样操作会导致一个读action在提交时和最终所看到的写action是不一样的。

事实上，我们可以将这里的$Ai$放宽为$A$，改为$r\in A-C_{i-1}$，意思是，所有未提交的以及当前正在提交的读action所能看到的写action都应该满足happen-before关系。只有当一个读action被提交后，它才有机会看到与它有data race的写action。

接着看rule 5，这一条不是很容易理解，为什么要对上一步的集合$C_{i-1}$进行限制呢？在rule 6中我们讲了，一个读action在提交时和最终所看到的写action可能是不一样的，那么改变在什么时候发生呢？根据rule 5，我们可以看出改变发生在提交读action后的下一个步。rule 5规定了对于上一步所得集合$C_{i-1}$中的每个读action，在这一步中它所看见的写action需要和最终它所看见的写action一样，也就是说，如果要做出改变，必须在这一步改变完并且固定下来。

如果将rule 5的限制改为$C_i$又会怎样呢？根据rule 6，正在提交的读action所看见的写action与其满足happen-before关系，改变后的rule 5又会限制这个所看见的写action与最终该读action所看见的写action一致，也就是说所有提交的读action永远都只能看见与其满足happen-before关系的写action，这依然禁止了data race的发生。

事实上，我们过去过来就在讲同一件事，一个读action在什么时候能看到与其有data race关系的写action。

前两条弄明白了再看rule 7就比较简单了。rule7包含两条规则：
- $W_i(r)\in C_{i-1}$规定了rule 6中满足happen-before的写action必须已经提交过了。
- $W(r)\in C_{i-1}$规定了读action最终所看见的写action也必须已经提交过了，这里有两层意思：

  - 第一、如果读action所看见的写action不变(即一直是当前这一步中所看见的满足happen-before关系的写action)，那么这两个规则表达的是同一个意思，即该写action必须已经提交了。
  - 第二、如果读action所看见写action会变，根据rule 5，当前所提交的写action在下一步可以改为看见满足data race的写action，但是该写action必须在上一步已经提交过了。

总之，rule 7的两条限制了一个读action所能看见的写action必须在它之前提交。

再来看rule 7的第二个规则。这个规则使用了$W(r)$，表达的是最终的结果，这里并没有限制改变会发生在哪一个步，根据rule 5我们可以得出改变发生在下一步，因此我们可以将`$W(r)\in C_{i-1}$`改为`$W_{i+1}(r)\in C_{i-1}$`。事实上，进一步分析可知，当前为第i步，rule 5在这里的上下文中所讲的是下一步i+1，因此在当前这一步中可将rule 5写为`${W_{i+1}|C_{i}=W|C_{i}}$`，由于`$r\in C_i-C_{i-1} \in C_i$`，所以有$W_{i+1}(r)=W(r)$，进而得出$W_{i+1}(r)\in C_{i-1}$。

## 3 举例
这一部分根据上面几条rules的描述来检验一下完整的提交流程，所使用的例子在前面出现过，为了方便，这里重新贴出来：
```
init:x = y = 0

Thread1        | Thread2
---------------|----------
r3 = x         | r2 = y
if (r3 == 0)   | x = r2
  x = 42       |    
r1 = x         |   
y = r1         |    

output: r1 == r2 == r3 == 42
```
提交流程如下表所示，Action即被操作的对象，Value指当前所写或所读的值，Commited In指明Action是在哪一个步中被提交的，Final Value In指明在哪一步中Action所看见的值被固定下来。
```
Action    | Value | Commited In | Final Value In | index
----------|-------|-------------|----------------|-------
x  = 0    | 0     | C1          | E1             |   1
y  = 0    | 0     | C1          | E1             |   2
y  = 42   | 42    | C1          | E1             |   3
r2 = y    | 0     | C2          | E2             |   4
r2 = y    | 42    | C2          | E3             |   5
x  = r2   | 42    | C3          | E3             |   6
r3 = x    | 0     | C4          | E4             |   7
r3 = x    | 42    | C4          | E5             |   8
r1 = x    | 0     | C5          | E5             |   9
r1 = x    | 42    | C5          | E6             |   10
```
根据前面的分析y = 42可以被提前。一开始集合为空集，此时提交r2 = y并不能使其看到42。所以第一步需要提交y = 42以及初始化的两个action，第二步提交r2 = y，注意第4行中Value为0，因为根据rule 6此时r2 = y只能看见与其满足happen-before的值，也就是y = 0。根据rule 5和rule 7，在第三步中我们可以让r2 = y看见y = 42，除此之外，第三步还必须再提交其他的action，不然上一节所提到的几条rule会因为i不满足关系而失效，因此在第三步中我们提交x = r2。从第四步开始我们回到Thread1，首先提交r3 = x，同前面r2 = y的分析，此时r3 = x还只能看见x = 0。接着在第五步中让r3 = x看见x = r2写入的值，并提交r1 = x，同样的道理，提交时只能看见满足happen-before关系的写action，虽然x = 42 happen-before r1 = x，但是根据rule 7，一个读所能看见的写必须先行提交，由于x = 42并未提交，所以r1 = x此时仍然只能看见x = 0。在最后的第六步中，我们将r1 = x修改为可以看见x = r2写入的值，也就是42。到此便完成了全部提交。

参考：
- [1: The Java Memory Model by. Jeremy Manson](http://www.cs.umd.edu/~pugh/java/memoryModel/Dagstuhl.pdf)
- [2: Causality Test Cases](http://www.cs.umd.edu/~pugh/java/memoryModel/unifiedProposal/testcases.html)
- [3: The Java Language Specification](https://docs.oracle.com/javase/specs/jls/se7/html/index.html)
- [4: The Java Memory Model: a Formal Explanation](https://gpetri.github.io/publis/jmm-vamp07.pdf)