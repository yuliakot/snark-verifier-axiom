# Gemini bizarre sumcheck 
### [section 2.4 here](https://eprint.iacr.org/2022/420.pdf)
### Setup:
Let $(f_0, f_1, \ldots, f_n)$, $(g_0, g_1, \ldots, g_n)$ be two sets of numbers.

**Goal:** prove that $f_0g_0 + f_1g_1 + \ldots = u$.

**Step #1:** We compute single-variate polynomials 

$$f(X) = \sum_i f_i X^i$$

$$g(X) = \sum_i g_i X^i$$


**Step #2:** We use the notatation $f_i = f_{(b_0, b_1, \ldots)}$ if $(b_0, b_1, \ldots)$ is the bit decomposition of $i$. We assume here that $b_0$ is the least significant bit of $i$, i.e.

$ b_0 = 0 \iff 2 | i.$

We compute multilinear polynomials 

$$\hat{f}(X) = \sum_{(b_0, b_1, \ldots)\in \{0, 1\}^k} f_{(b_0, b_1, \ldots)}X_0^{b_0}X_1^{b_1}\ldots$$

$$\hat{g}(X) = \sum_{(b_0, b_1, \ldots)\in \{0, 1\}^k} g_{(b_0, b_1, \ldots)}X_0^{b_0}X_1^{b_1}\ldots$$

**Lemma:**
$$\sum_{\omega \in \{-1, 1\}^k} \hat{f}(\omega)\hat{g}(\omega) = u.$$

*Hint: only powers $0$, $1$ or $2$ appear for each variable $X_j$ in each monomial in $\hat{f}(X)\hat{g}(X)$.*

We will be using polynomials $\hat{f}$ and $\hat{g}$ to produce a proof for 

**Reduction #1:** Prove that 
$$\sum_{\omega \in \{-1, 1\}^k} \hat{f}(\omega)\hat{g}(\omega) = u.$$


**Some observations:**
This is a special case of sumcheck. We will realize the standard sumcheck protocol for $\hat{f}\hat{g}$ by only querying $f$ and $g$. Consider the first round of the standard sumcheck protocol:  the verifier would provide a challenge  $\rho_0$ and the prover would compute the polynomial 
$$\hat{f}(\rho_0, X_1, \ldots) \hat{g}(\rho_0, X_1, \ldots).$$

**Step #3: One round of sumcheck:**
Consider the univariate polynomial 

$$f'(X) = \sum_i f_{2i} X^{2i} + \rho_0 \sum_i f_{2i+1} X^{2i} = f_e(X^2) + \rho_0 f_o(X^2)$$ 
(not the derivative) and let $f'_0, f'_1, \ldots$ be its coefficients. Then the corresponding multilinear polynomial 
$
\hat{f'}(X_1, X_2, \ldots)
$ constructed as above has the property
$$
\hat{f'}(X_1, X_2, \ldots) = \hat{f}(\rho_0, X_1, X_2, \ldots).
$$

To check that $f'$ and $f$ are related as claimed, the verifier provides a random challenge $\beta_0$ and checks that
$$
f'(\beta_0) = f_e(\beta_0) + \rho_0 f_o(\beta_0) = \frac{f(\beta_0) + f(-\beta_0)}{2} + \rho_0\frac{f(\beta_0) - f(-\beta_0)}{2\beta_0}.
$$
Hence we con compute $\hat{f}(\rho_0, X_1, \ldots) \hat{g}(\rho_0, X_1, \ldots)$ by only querying $f$ and $f'$. 

