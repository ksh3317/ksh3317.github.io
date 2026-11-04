# 글 템플릿

새 글을 쓸 때 복사해서 쓰는 템플릿입니다. 이 폴더는 이름이 `_`로 시작해서 블로그에는 올라가지 않습니다.

| 파일 | 용도 |
|---|---|
| `project.md` | 개발 프로젝트 |
| `ctf-wargame.md` | CTF/Wargame 문제 풀이 |
| `activity.md` | 컨퍼런스, 공모전, 자격증, 교육 등 활동 기록 |

## 새 글 만드는 순서

```bash
cd ~/Knights_Frontier/ksh3317.github.io

# 1. 템플릿 복사 (날짜-영문이름.md)
cp _templates/ctf-wargame.md _posts/2026-11-10-dreamhack-xss.md

# 2. 이미지 폴더 만들기 (글 파일 이름에서 날짜를 뺀 이름으로)
mkdir -p assets/img/posts/dreamhack-xss
```

3. 캡처한 이미지나 영상을 `assets/img/posts/dreamhack-xss/` 폴더에 넣습니다.
4. 글을 열어 `title`, `date`를 바꾸고 내용을 씁니다.
5. 이미지를 넣을 곳의 `{% comment %}` 안 예시를 밖으로 꺼내 경로를 바꿉니다.

## 주의

- `date`의 `YYYY-MM-DD HH:MM:SS`를 꼭 실제 날짜로 바꿔야 합니다. 그대로 두면 배포가 실패합니다.
- 대표 이미지(`image:`)는 이미지를 넣은 뒤에 앞의 `#`를 지워서 켭니다. 없는 파일 경로를 적으면 배포가 실패합니다.
- `{% comment %}` ~ `{% endcomment %}` 사이의 내용은 블로그에 보이지 않습니다. 안내문이 필요 없으면 지워도 됩니다.
- 쓰지 않는 섹션은 지워도 됩니다.

## 이미지, 동영상 문법

```markdown
![설명](/assets/img/posts/폴더이름/파일.png){: w="600" }
_이미지 아래에 보일 설명_
```

```markdown
{% include embed/video.html src='/assets/img/posts/폴더이름/파일.mp4' %}
```

```markdown
{% include embed/youtube.html id='유튜브영상ID' %}
```

- 이미지는 1MB 이하, 영상은 10MB 이하를 권장합니다. 긴 영상은 유튜브(일부 공개)에 올려 연결합니다.
- 올리기 전에 개인정보, 플래그 값, 토큰, 다른 사람의 얼굴과 이름을 가립니다.
